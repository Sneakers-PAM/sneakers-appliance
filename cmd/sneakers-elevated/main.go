// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command sneakers-elevated runs one root shell for a root operator's
// ticket (spec 2, Section 2.8). accessd starts it, as root, for each
// connection to its root-shell socket that carries a ticket: its standard
// input and output are that connection, the ticket and the admin come in
// its environment, and the terminal sizes arrive in the connection's
// frames (internal/rootshell). It has accessd use the ticket up before the
// prompt, holds the time box and the idle timer itself, and ends at the
// limit; SIGTERM (an owner's terminate, through accessd) ends it early.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/sys/unix"

	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevated"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootshell"
)

const auditDir = "/var/lib/sneakers/os-audit"

// The environment accessd hands over.
const (
	envTicket = "SNEAKERS_ROOT_TICKET"
	envAdmin  = "SNEAKERS_ROOT_ADMIN"
	envRows   = "SNEAKERS_ROOT_ROWS"
	envCols   = "SNEAKERS_ROOT_COLS"
)

func main() { os.Exit(run()) }

func run() int {
	lg := log.NewLoggerWithOptions("sneakers-elevated", log.WithOutput(os.Stderr), log.WithDefaultFormat(log.FormatJSON), log.WithDefaultLevel(log.LevelError))
	if os.Geteuid() != 0 {
		_, _ = fmt.Fprintln(os.Stderr, "sneakers-elevated runs only for accessd's root-shell socket.")
		return 1
	}
	ticket, admin := os.Getenv(envTicket), os.Getenv(envAdmin)
	_ = os.Unsetenv(envTicket)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT)
	defer stop()
	terminated, stopTerm := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stopTerm()
	audit, err := osaudit.Open(auditDir, osaudit.Options{Logger: lg})
	if err != nil {
		lg.Error(err, "elevated: the OS audit log can't be opened")
		_, _ = fmt.Fprint(os.Stdout, "\r\nThe session can't be recorded, so it doesn't start.\r\n")
		return 1
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", accessapi.SocketPath)
		},
	}}
	sizes := make(chan [2]uint16, 4)
	if r, c := atoi(os.Getenv(envRows)), atoi(os.Getenv(envCols)); r > 0 && c > 0 {
		sizes <- [2]uint16{r, c}
	}
	in := rootshell.NewReader(os.Stdin, func(rows, cols uint16) {
		select {
		case sizes <- [2]uint16{rows, cols}:
		default:
		}
	})
	o := elevated.Options{
		Accessd: accessv1connect.NewElevationServiceClient(hc, "http://access.sock"),
		Ticket:  ticket, Admin: admin, Audit: audit, In: in, Out: os.Stdout, PID: os.Getpid(), Logger: lg,
		Resize: func(ctx context.Context, pty *os.File) {
			for {
				select {
				case <-ctx.Done():
					return
				case sz := <-sizes:
					_ = unix.IoctlSetWinsize(int(pty.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: sz[0], Col: sz[1]}) // #nosec G115 -- a file descriptor
				}
			}
		},
	}
	res, err := elevated.Run(ctx, terminated, o)
	if err != nil {
		lg.Error(err, "elevated: the session didn't run", log.F("id", res.ID))
		_, _ = fmt.Fprintf(os.Stdout, "\r\n%v\r\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(os.Stdout, "\r\nRoot shell %s ended (%s).\r\n", res.ID, res.Reason)
	return 0
}

func atoi(s string) uint16 {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}
