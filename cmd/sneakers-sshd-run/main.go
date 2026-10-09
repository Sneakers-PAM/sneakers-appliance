// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command sneakers-sshd-run renders, checks and runs OpenSSH sshd: it
// refuses to start while no admin can sign in, installs the config only once
// the pinned sshd -t accepts it, runs sshd -D -e -f on it, and on a
// SIGHUP from accessd, or new management addresses from netd, renders and
// checks again before it tells sshd.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1/netdv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netdapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshconfig"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshdrun"
)

type config struct {
	configDir, state, sshd, netdSock, pidFile string
}

func main() {
	var c config
	flag.StringVar(&c.configDir, "config-dir", "/run/sneakers/ssh", "where the rendered files live")
	flag.StringVar(&c.state, "state", "/var/lib/sneakers", "the state volume")
	flag.StringVar(&c.sshd, "sshd", "/usr/sbin/sshd", "the pinned sshd")
	flag.StringVar(&c.netdSock, "netd-socket", netdapi.SocketPath, "netd's socket")
	flag.StringVar(&c.pidFile, "pid-file", "/run/sneakers/sshd.pid", "where this process's pid goes; accessd signals it")
	flag.Parse()
	lg := log.NewLoggerWithOptions("sneakers-sshd-run", log.WithOutput(os.Stderr), log.WithDefaultFormat(log.FormatJSON), log.WithDefaultLevel(log.LevelError))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := run(ctx, c, lg); err != nil {
		lg.Error(err, "sshd-run: fatal")
		_, _ = fmt.Fprintln(os.Stderr, "sneakers-sshd-run:", codes.Describe(err))
		os.Exit(1)
	}
}

func run(ctx context.Context, c config, lg log.Logger) error {
	if err := os.WriteFile(c.pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil { // #nosec G306 -- a pid file
		return err
	}
	if err := sshconfig.EnsurePrivsepDir(sshconfig.PrivsepDir); err != nil {
		return err
	}
	defer func() { _ = os.Remove(c.pidFile) }()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	netd := netdapi.NewClient(c.netdSock)
	audit, err := osaudit.Open(filepath.Join(c.state, "os-audit"), osaudit.Options{Logger: lg})
	if err != nil {
		lg.Error(err, "sshd-run: the OS audit log isn't open; refusals are only logged")
		audit = nil
	}
	paths := sshconfig.DefaultPaths()
	paths.ConfigDir = c.configDir
	o := sshdrun.Options{
		Paths: paths, StateDir: c.state,
		Addresses: func(ctx context.Context) ([]netip.Addr, error) {
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			st, err := netd.Status(cctx, connect.NewRequest(&netdv1.StatusRequest{}))
			if err != nil {
				return nil, err
			}
			return netdapi.Bindable(st.Msg.GetManagementAddresses()), nil
		},
		Check:  func(dir string) error { return sshconfig.Check(c.sshd, dir) },
		Logger: lg,
	}
	lw := sshdrun.LogWatchOptions{StateDir: c.state, Out: os.Stderr, Logger: lg}
	if audit != nil {
		o.Audit = audit
		lw.Audit = audit
	}
	// sshd's log passes through the watch, which audits a box-issued key
	// sent without its certificate.
	o.Start = sshdrun.Exec(c.sshd, sshdrun.NewLogWatch(lw))
	r := sshdrun.New(o)
	if err := r.Prepare(ctx); err != nil {
		return err
	}
	reload := make(chan struct{}, 1)
	kick := func() {
		select {
		case reload <- struct{}{}:
		default:
		}
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				lg.Info("sshd-run: SIGHUP; rendering again")
				kick()
			}
		}
	}()
	go watch(ctx, netd, lg, kick)
	return r.Run(ctx, reload)
}

// watch follows netd's address events and asks for a render on each one
// after the first; a broken stream is opened again.
func watch(ctx context.Context, netd netdv1connect.NetworkServiceClient, lg log.Logger, kick func()) {
	for ctx.Err() == nil {
		stream, err := netd.Watch(ctx, connect.NewRequest(&netdv1.WatchRequest{}))
		if err == nil {
			first := true
			for stream.Receive() {
				if !first {
					lg.Info("sshd-run: the management addresses changed; rebinding", log.F("addresses", fmt.Sprint(stream.Msg().GetManagementAddresses())))
					kick()
				}
				first = false
			}
			err = stream.Err()
			_ = stream.Close()
		}
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("the stream ended")
		}
		lg.Warn("sshd-run: netd's address events stopped; watching again", log.F("error", err.Error()))
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
		kick()
	}
}
