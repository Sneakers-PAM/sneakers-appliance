// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command sneakers-netd is the network daemon: addresses, DHCP, router
// advertisements, resolv.conf, SNTP, the management firewall and the
// connectivity checks, served on /run/sneakers/netd.sock to root.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	// The root has no zoneinfo; the box's time zone setting is read from
	// the copy linked in.
	_ "time/tzdata"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxname"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netdapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/ovfenv"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/timesync"
)

type config struct {
	state, run, socket string
}

func main() {
	var c config
	flag.StringVar(&c.state, "state", "/var/lib/sneakers", "the state volume")
	flag.StringVar(&c.run, "run", "/run/sneakers", "where resolv.conf, the socket and the readiness file live")
	flag.StringVar(&c.socket, "socket", netdapi.SocketPath, "netd's socket")
	flag.Parse()
	lg := log.NewLoggerWithOptions("sneakers-netd", log.WithOutput(os.Stderr), log.WithDefaultFormat(log.FormatJSON), log.WithDefaultLevel(log.LevelError))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, c, lg); err != nil {
		lg.Error(err, "netd: fatal")
		_, _ = fmt.Fprintln(os.Stderr, "sneakers-netd:", codes.Describe(err))
		os.Exit(1)
	}
}

// offeredHostname is the host name a VMware deployment set in the OVA's
// vApp properties, from the OVF environment ISO in the CD drive; none
// elsewhere.
func offeredHostname(own string, lg log.Logger) string {
	env, err := ovfenv.Read(ovfenv.Devices)
	if errors.Is(err, ovfenv.ErrNone) {
		lg.Info("netd: no OVF environment; the deployment offers no host name")
		return ""
	}
	if err != nil {
		lg.Warn("netd: the OVF environment can't be read; the deployment's host name is ignored", log.F("error", err.Error()))
		return ""
	}
	h := env.Hostname(own)
	if h == "" && (env[ovfenv.KeyHostname] != "" || env[ovfenv.KeyDomain] != "") {
		lg.Warn("netd: the deployment's host name and domain make no fully qualified name; set one on Network", log.F("hostname", env[ovfenv.KeyHostname]), log.F("domain", env[ovfenv.KeyDomain]))
	}
	return h
}

// buildTime is the image's build time, the clock floor's starting point:
// the reproducible root build stamps every file with SOURCE_DATE_EPOCH.
func buildTime() time.Time {
	exe, err := os.Executable()
	if err != nil {
		return time.Time{}
	}
	fi, err := os.Stat(exe)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

func run(ctx context.Context, c config, lg log.Logger) error {
	own, err := boxname.Ensure(c.state)
	if err != nil {
		lg.Warn("netd: the box has no name of its own; the host name waits for the settings or DHCP", log.F("error", err.Error()))
	}
	// netd audits the clock's steps in the box's OS audit log, which the
	// other root daemons append to under the same lock.
	var audit osaudit.Appender
	if l, err := osaudit.Open(filepath.Join(c.state, "os-audit"), osaudit.Options{Logger: lg}); err == nil {
		audit = l
	} else {
		lg.Warn("netd: the OS audit log can't be opened; clock steps are only logged", log.F("error", err.Error()))
	}
	d, err := netd.New(netd.Options{
		Fallback: own,
		Offered:  func() string { return offeredHostname(own, lg) },
		StateDir: c.state, RunDir: c.run,
		Sys:         netd.Linux{},
		Workers:     netd.Clients{Logger: lg},
		NewTimeSync: netd.TimeSyncs(timesync.SystemClock(), filepath.Join(c.state, "netd", "clock-floor"), buildTime(), lg, audit),
		Logger:      lg,
		Audit:       audit,
	})
	if err != nil {
		return err
	}
	if err := d.Start(ctx); err != nil {
		return err
	}
	srv, err := netd.Listen(c.socket, d, lg)
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()
	ready := filepath.Join(c.run, "netd.ready")
	if err := os.WriteFile(ready, nil, 0o644); err != nil { // #nosec G306 -- an empty readiness marker
		return err
	}
	defer func() { _ = os.Remove(ready) }()
	lg.Info("netd: ready", log.F("socket", c.socket))
	// One plain line per change on the console, whatever the log level: the
	// address is what an admin at the console needs first.
	addrs, stopWatch := d.Watch()
	defer stopWatch()
	go func() {
		for a := range addrs {
			_, _ = fmt.Fprintf(os.Stderr, "sneakers-netd: management addresses %s\n", strings.Join(a.Management, " "))
		}
	}()
	<-ctx.Done()
	lg.Info("netd: stopped")
	return nil
}
