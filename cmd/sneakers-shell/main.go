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
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

// offline answers every call while accessd's socket is unreachable.
type offline struct{}

func (offline) Call(context.Context, shell.Request) (shell.Result, error) {
	return shell.Result{}, shell.ErrUnavailable
}

func backend() shell.Backend { return offline{} }

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
