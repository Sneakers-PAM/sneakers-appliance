// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command sneakers-init is PID 1 on the appliance: it mounts the early
// filesystems, reaps every child, decides the boot phase, runs the enrol
// phase, finishes an interrupted factory reset, supervises the service
// table, and serves init.sock and power.sock (reboot, shutdown and the
// factory reset).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/sys/unix"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/reaper"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/services"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/switchroot"
)

// Paths on the box.
const (
	espMount  = "/run/sneakers/esp"
	setupDone = "/var/lib/sneakers/setup/done"
)

func main() {
	lg := log.NewLoggerWithOptions("sneakers-init", log.WithOutput(os.Stderr), log.WithDefaultFormat(log.FormatConsole), log.WithDefaultLevel(log.LevelInfo))
	if os.Getpid() != 1 {
		lg.Error(nil, "sneakers-init must run as PID 1")
		os.Exit(1)
	}
	if err := run(lg); err != nil {
		lg.Error(err, "init: fatal")
		_, _ = fmt.Fprintln(os.Stderr, "sneakers-init:", codes.Describe(err))
	}
	// PID 1 must never exit: halt here so the console keeps the error.
	select {}
}

func run(lg log.TraceLogger) error {
	mountEarly(lg)
	r := reaper.NewReaper()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	pins, perr := release.Load()
	if perr != nil {
		lg.Error(perr, "init: this build carries no pins; Secure Boot can't be checked as org-only")
	}
	espOK := mountESP(lg)
	f := phase.Facts{BootedFromISO: os.Getenv(switchroot.SourceEnv) == switchroot.SourceInstall}
	var vars secureboot.Vars
	if e := (secureboot.Efivarfs{Dir: secureboot.DefaultEfivarfs}); e.Present() {
		vars = e
	}
	var pp *release.Pins
	if perr == nil {
		pp = &pins
	}
	st, err := secureboot.Read(vars, pp)
	if err != nil {
		lg.Error(err, "init: Secure Boot state unknown")
	}
	f.SBSupported, f.SBEnforcing, f.SBEnforcingOrgOnly = st.Supported, st.Enforcing, st.Enforcing && st.OrgOnly
	if espOK {
		if c, err := secureboot.ReadChoice(espMount); err == nil {
			f.SBChoice = phase.SB(c)
		}
	}
	if _, err := os.Stat(setupDone); err == nil {
		f.SetupDone = true
	}
	f.ResetPending = readReset(espOK, lg)
	p := phase.Decide(f)
	_, _ = fmt.Fprintf(os.Stderr, "sneakers-init: phase=%s protection=%s\n", p, protection(st, f))
	lg.Info("init: phase decided", log.F("phase", string(p)), log.F("secure_boot", st.Enforcing), log.F("setup_mode", st.SetupMode))

	switch p {
	case phase.Reset:
		return finishReset(ctx, lg)
	case phase.Mismatch:
		_, _ = fmt.Fprint(os.Stderr, screens.Mismatch)
		<-ctx.Done()
		return nil
	case phase.Enrol:
		out, err := runEnrol(enrolDeps{
			vars:      vars,
			material:  func() (secureboot.Material, error) { return secureboot.LoadMaterial(os.DirFS(espMount)) },
			choice:    string(f.SBChoice),
			setChoice: func(c string) error { return secureboot.WriteChoice(espMount, c) },
			platform:  screens.DetectPlatform(readFile("/sys/class/dmi/id/sys_vendor")),
			in:        os.Stdin,
			out:       os.Stderr,
			logf:      func(format string, a ...any) { lg.Info(fmt.Sprintf(format, a...)) },
		})
		if err != nil {
			return err
		}
		if out == enrolReboot {
			if screens.DetectPlatform(readFile("/sys/class/dmi/id/sys_vendor")) == screens.QEMU {
				unix.Sync()
				return unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
			}
			<-ctx.Done()
			return nil
		}
		p = phase.Firstboot
	}

	tbl, err := services.Load(os.DirFS("/"), services.Dir)
	if err != nil {
		return err
	}
	sup := services.NewSupervisor(r, tbl, services.Options{Logger: lg})
	pw := newPower(sup, lg)
	api := initapi.Options{Supervisor: sup, Power: pw, AdminName: adminName, Logger: lg}
	srv, err := initapi.Listen(initapi.SocketPath, api)
	if err != nil {
		return err
	}
	defer srv.Stop()
	psrv, err := initapi.ListenPower(initapi.PowerSocketPath, api)
	if err != nil {
		return err
	}
	defer psrv.Stop()
	if err := sup.EnterPhase(ctx, p); err != nil {
		return err
	}
	<-ctx.Done()
	lg.Info("init: shutting down")
	_ = sup.EnterPhase(context.Background(), "")
	unix.Sync()
	return nil
}

func protection(st secureboot.State, f phase.Facts) string {
	if st.Enforcing && st.OrgOnly {
		return "full"
	}
	if !st.Supported {
		return "reduced (no Secure Boot firmware)"
	}
	if f.SBChoice == phase.SBOff {
		return "reduced (Secure Boot off)"
	}
	return "pending"
}

// earlyMounts are what every later step needs. nosuid and nodev are mount
// flags (passed as flags to every one of them), never filesystem data: tmpfs
// refuses an option it doesn't know with EINVAL.
var earlyMounts = []struct{ src, dst, fstype, data string }{
	{"proc", "/proc", "proc", ""},
	{"sysfs", "/sys", "sysfs", ""},
	{"devtmpfs", "/dev", "devtmpfs", "mode=0755"},
	{"tmpfs", "/run", "tmpfs", "mode=0755"},
	{"tmpfs", "/tmp", "tmpfs", "mode=1777"},
	{"efivarfs", secureboot.DefaultEfivarfs, "efivarfs", ""},
}

// mountEarly mounts earlyMounts. Errors are logged, not fatal: a missing
// efivarfs, for instance, just means no Secure Boot.
func mountEarly(lg log.Logger) {
	for _, m := range earlyMounts {
		_ = os.MkdirAll(m.dst, 0o755) // #nosec G301 -- standard mount points
		if err := unix.Mount(m.src, m.dst, m.fstype, unix.MS_NOSUID|unix.MS_NODEV, m.data); err != nil && err != unix.EBUSY {
			lg.Warn("init: mount", log.F("target", m.dst), log.F("error", err.Error()))
		}
	}
}

// mountESP mounts the boot disk's ESP (the partition labelled ESP).
func mountESP(lg log.Logger) bool {
	parts, err := switchroot.NewSystem().Partitions()
	if err != nil {
		return false
	}
	for _, p := range parts {
		if p.Label == "ESP" {
			_ = os.MkdirAll(espMount, 0o700)
			if err := unix.Mount(p.Device, espMount, "vfat", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "umask=0077"); err != nil {
				lg.Warn("init: mount the ESP", log.F("device", p.Device), log.F("error", err.Error()))
				return false
			}
			return true
		}
	}
	return false
}

func readFile(p string) string {
	b, err := os.ReadFile(filepath.Clean(p))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
