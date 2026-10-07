// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command sneakers-netd is the network daemon: addresses, DHCP, router
// advertisements, resolv.conf, SNTP, the management firewall and the
// connectivity checks, served on /run/sneakers/netd.sock to root.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netdapi"
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
	d, err := netd.New(netd.Options{
		StateDir: c.state, RunDir: c.run,
		Sys:         netd.Linux{},
		Workers:     netd.Clients{Logger: lg},
		NewTimeSync: netd.TimeSyncs(timesync.SystemClock(), filepath.Join(c.state, "netd", "clock-floor"), buildTime(), lg),
		Logger:      lg,
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
