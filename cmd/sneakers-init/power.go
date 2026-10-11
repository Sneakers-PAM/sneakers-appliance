// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/sys/unix"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/console"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/factoryreset"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/power"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/services"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/switchroot"
)

// Where init finds what the power controller reads, on the state volume.
const (
	stateDir   = "/var/lib/sneakers"
	cryptsetup = "/usr/sbin/cryptsetup"
)

// bootDisk is the disk holding the ESP, or "" when there's none.
func bootDisk() string {
	parts, err := switchroot.NewSystem().Partitions()
	if err != nil {
		return ""
	}
	for _, p := range parts {
		if p.Label == disk.LabelESP {
			return diskOf(p.Device)
		}
	}
	return ""
}

func resetDeps(lg log.Logger) (factoryreset.Deps, error) {
	dev := bootDisk()
	if dev == "" {
		return factoryreset.Deps{}, codes.New(codes.ResetFailed, "the boot disk (the one with the ESP) wasn't found")
	}
	return factoryreset.Deps{
		Store: factoryreset.FileStore{Dir: espMount},
		Disk:  &factoryreset.GPTDisk{Path: dev, Notify: factoryreset.KernelForget(dev)},
		Logf: func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			_, _ = fmt.Fprintln(os.Stderr, "sneakers-init:", msg)
			lg.Warn(msg)
		},
	}, nil
}

// readReset reports whether the ESP records an unfinished factory reset.
// A record that can't be read counts as unfinished: the box must not boot
// normally on a reset it can't account for.
func readReset(espOK bool, lg log.Logger) bool {
	if !espOK {
		return false
	}
	rec, ok, err := factoryreset.FileStore{Dir: espMount}.Read()
	if err != nil {
		lg.Error(err, "init: the factory reset record doesn't read; treating it as unfinished")
		return true
	}
	return ok && rec.Pending()
}

// finishReset carries an interrupted factory reset on at boot, before
// anything starts, then reboots into first boot. On failure it returns the
// error and init halts with it on the console; it never boots normally.
func finishReset(ctx context.Context, lg log.Logger, con *console.Taken, screen bootScreen) error {
	_, _ = fmt.Fprintln(os.Stderr, "sneakers-init: a factory reset is unfinished; finishing it")
	d, err := resetDeps(lg)
	if err != nil {
		return err
	}
	rec, err := factoryreset.Run(ctx, d)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "sneakers-init: the factory reset can't finish; this box won't boot normally until it does:", codes.Describe(err))
		return err
	}
	lg.Warn("init: factory reset finished; rebooting into first boot", log.F("id", rec.ID), log.F("attempts", rec.Attempts))
	screen.stopping(osaudit.ActionReboot)
	con.Flush(flushWait)
	unix.Sync()
	_ = unix.Unmount(espMount, 0)
	unix.Sync()
	return unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
}

// lazyAudit opens the OS audit log on the state volume the first time a
// power request needs it, and again after a failure.
type lazyAudit struct {
	mu  sync.Mutex
	log *osaudit.Log
	lg  log.Logger
}

func (a *lazyAudit) open() (power.Auditor, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.log == nil {
		l, err := osaudit.Open(filepath.Join(stateDir, "os-audit"), osaudit.Options{Logger: a.lg})
		if err != nil {
			return nil, err
		}
		a.log = l
	}
	return a.log, nil
}

// noReset answers when the boot disk isn't known.
type noReset struct{ err error }

func (n noReset) Begin(factoryreset.Record) (factoryreset.Record, error) {
	return factoryreset.Record{}, n.err
}

func (n noReset) Run(context.Context, func(context.Context) error) (factoryreset.Record, error) {
	return factoryreset.Record{}, n.err
}

// flushedMachine puts the rebooting or shutting down page on the screen
// and lets the last lines reach every console before the power goes. It
// closes the kept console log before the volumes.
type flushedMachine struct {
	power.Linux
	con    *console.Taken
	screen bootScreen
	kept   *keptLog
}

func (m flushedMachine) CloseVolumes(ctx context.Context) error {
	return closeLogFirst(ctx, m.kept, m.Linux.CloseVolumes)
}

func (m flushedMachine) Reboot() error {
	m.screen.stopping(osaudit.ActionReboot)
	m.con.Flush(flushWait)
	return m.Linux.Reboot()
}

func (m flushedMachine) PowerOff() error {
	m.screen.stopping(osaudit.ActionShutdown)
	m.con.Flush(flushWait)
	return m.Linux.PowerOff()
}

func newPower(sup *services.Supervisor, lg log.Logger, con *console.Taken, screen bootScreen, kept *keptLog) *power.Controller {
	var reset power.Resetter
	if d, err := resetDeps(lg); err != nil {
		lg.Warn("init: no factory reset on this boot", log.F("error", codes.Describe(err)))
		reset = noReset{err: err}
	} else {
		reset = power.FactoryReset{Deps: d}
	}
	roster := func() (access.State, error) { return access.ReadState(filepath.Join(stateDir, "access")) }
	return power.New(power.Options{
		Machine:  flushedMachine{Linux: power.Linux{ESP: espMount, Cryptsetup: reaperRunner{binary: cryptsetup}, Logger: lg}, con: con, screen: screen, kept: kept},
		Announce: announce(boxstate.File, screen.stopping, lg),
		Keep:     drainKeep,
		Drainer:  sup,
		Audit:    (&lazyAudit{lg: lg}).open,
		Roster:   roster,
		Reset:    reset,
		Clock:    clock.Real{},
		Logger:   lg,
	})
}

// drainKeep is what a reboot's or a shutdown's drain leaves running until
// the power goes: the edge fallback answers 80 and 443 with the box-state
// page once k0s has stopped.
var drainKeep = []string{"edgefall"}

// announce is the power controller's Announce: the reboot or the shutdown
// goes to the box-state file first (the product edge's box-state page
// reads it through accessd's GetPhase and sneakers-edgefall), then on the
// screen. A file that can't be written is logged; the box still goes down.
func announce(file string, show func(action string), lg log.Logger) func(action string) {
	return func(action string) {
		s := boxstate.Rebooting
		if action == osaudit.ActionShutdown {
			s = boxstate.ShuttingDown
		}
		if err := boxstate.Announce(file, s); err != nil {
			lg.Error(err, "init: the box-state file wasn't written", log.F("state", string(s)))
		} else {
			lg.Info("init: the box state is announced", log.F("state", string(s)))
		}
		show(action)
	}
}

// adminName names the admin a closed-shell login's uid belongs to.
func adminName(uid uint32) (string, bool) {
	st, err := access.ReadState(filepath.Join(stateDir, "access"))
	if err != nil {
		return "", false
	}
	a, ok := st.AdminByUID(int(uid))
	if !ok {
		return "", false
	}
	return a.Name, true
}
