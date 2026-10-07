// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command sneakers-elevated is the maint account's shell and forced
// command: one approved, time-boxed, recorded root shell per elevation
// certificate (spec 2, Section 2.8). It has accessd use the certificate up
// before the prompt, holds the time box itself and ends the session at the
// approved length; SIGTERM (an owner's terminate, through accessd) ends it
// early.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/term"

	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevated"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

const auditDir = "/var/lib/sneakers/os-audit"

func main() { os.Exit(run()) }

func run() int {
	lg := log.NewLoggerWithOptions("sneakers-elevated", log.WithOutput(os.Stderr), log.WithDefaultFormat(log.FormatJSON), log.WithDefaultLevel(log.LevelError))
	if os.Geteuid() != 0 {
		_, _ = fmt.Fprintln(os.Stderr, "sneakers-elevated runs only as the maint account.")
		return 1
	}
	// SIGHUP is the client going away; it ends the session like an exit.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT)
	defer stop()
	terminated, stopTerm := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stopTerm()
	login, err := accessapi.LoginFromSSH(os.Getenv)
	if err != nil {
		lg.Error(err, "elevated: the login can't be read")
		_, _ = fmt.Fprintln(os.Stderr, "This login can't be used for elevation:", err)
		return 1
	}
	audit, err := osaudit.Open(auditDir, osaudit.Options{Logger: lg})
	if err != nil {
		lg.Error(err, "elevated: the OS audit log can't be opened")
		_, _ = fmt.Fprintln(os.Stderr, "The session can't be recorded, so it doesn't start.")
		return 1
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", accessapi.SocketPath)
		},
	}}
	o := elevated.Options{
		Accessd: accessv1connect.NewElevationServiceClient(hc, "http://access.sock"),
		Login:   login, Audit: audit, In: os.Stdin, Out: os.Stdout, PID: os.Getpid(), Logger: lg,
	}
	fd := int(os.Stdin.Fd()) // #nosec G115 -- a file descriptor
	if term.IsTerminal(fd) {
		old, err := term.MakeRaw(fd)
		if err == nil {
			defer func() { _ = term.Restore(fd, old) }()
		}
		o.Resize = func(ctx context.Context, pty *os.File) {
			_ = elevated.CopySize(os.Stdin, pty)
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, syscall.SIGWINCH)
			defer signal.Stop(ch)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ch:
					_ = elevated.CopySize(os.Stdin, pty)
				}
			}
		}
	}
	res, err := elevated.Run(ctx, terminated, o)
	if err != nil {
		lg.Error(err, "elevated: the session didn't run", log.F("id", res.ID))
		_, _ = fmt.Fprintf(os.Stderr, "\r\n%v\r\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(os.Stdout, "\r\nSession %s ended (%s).\r\n", res.ID, res.Reason)
	return 0
}
