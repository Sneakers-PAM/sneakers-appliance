// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command sneakers-shell is every admin's login shell and sshd's forced
// command: the closed shell of spec 2 Section 2.8. sshd starts it as
// "sneakers-shell -c <forced command>"; the arguments are ignored and the
// admin's own command, if any, comes from SSH_ORIGINAL_COMMAND.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

// osadminSocket is osadmin's local socket: sign-in approval.
const osadminSocket = "/run/sneakers/osadmin.sock"

func backend() *shell.Services {
	name := "unknown"
	if u, err := user.LookupId(strconv.Itoa(os.Getuid())); err == nil {
		name = u.Username
	}
	sess, err := shell.SessionFromSSH(os.Getenv, name)
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", osadminSocket)
		},
	}, Timeout: 30 * time.Second}
	return &shell.Services{Session: sess, SessionErr: err, Local: osadminv1connect.NewLocalServiceClient(hc, "http://osadmin.sock")}
}

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	e := &shell.Env{Origin: shell.OriginSSH, Backend: backend(), In: os.Stdin, Out: os.Stdout, Err: os.Stderr}
	if line := os.Getenv("SSH_ORIGINAL_COMMAND"); line != "" {
		if err := shell.Run(ctx, e, line); err != nil {
			return 1
		}
		return 0
	}
	fd := int(os.Stdin.Fd()) // #nosec G115 -- a file descriptor fits an int
	if !term.IsTerminal(fd) {
		_, _ = fmt.Fprintln(os.Stderr, "Give a command (ssh <admin>@<address> status) or log in with a terminal.")
		return 1
	}
	old, err := term.MakeRaw(fd)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "can't set up the terminal:", err)
		return 1
	}
	defer func() { _ = term.Restore(fd, old) }()
	host, _ := os.Hostname()
	prompt := fmt.Sprintf("%s@%s> ", os.Getenv("USER"), host)
	rw := struct {
		io.Reader
		io.Writer
	}{os.Stdin, os.Stdout}
	if err := shell.Interactive(ctx, e, rw, prompt); err != nil {
		return 1
	}
	return 0
}
