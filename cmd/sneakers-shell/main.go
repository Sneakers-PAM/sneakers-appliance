// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Command sneakers-shell is every admin's login shell and sshd's forced
// command: the closed shell of spec 2 Section 2.8. sshd starts it as
// "sneakers-shell -c <forced command>"; the arguments are ignored and the
// admin's own command, if any, comes from SSH_ORIGINAL_COMMAND. Before
// anything else it asks for the admin's TOTP code, which accessd checks
// under the lockout; a wrong code ends the login.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

// The local sockets: init's power socket for reboot and poweroff.
const powerSocket = "/run/sneakers/power.sock"

func unixClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}, Timeout: 30 * time.Second}
}

func backend() *shell.Services {
	name := "unknown"
	if u, err := user.LookupId(strconv.Itoa(os.Getuid())); err == nil {
		name = u.Username
	}
	sess, err := shell.SessionFromSSH(os.Getenv, name)
	s := &shell.Services{
		Session: sess, SessionErr: err,
		Power:      initv1connect.NewPowerServiceClient(unixClient(powerSocket), "http://power.sock"),
		StatusFile: accessapi.StatusFile,
	}
	s.UseAccessd(unixClient(accessapi.SocketPath), "http://access.sock")
	return s
}

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	b := backend()
	fd := int(os.Stdin.Fd()) // #nosec G115 -- a file descriptor fits an int
	tty := term.IsTerminal(fd)
	code, err := askCode(fd, tty)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "\nNo authenticator code; the login ends.")
		return 1
	}
	login, err := b.VerifyTotp(ctx, code)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, codes.Describe(err))
		return 1
	}
	defer b.EndLogin(context.WithoutCancel(ctx), login)
	e := &shell.Env{Origin: shell.OriginSSH, Backend: b, In: os.Stdin, Out: os.Stdout, Err: os.Stderr}
	if tty {
		e.RootShell = rootShell(fd)
	}
	if line := os.Getenv("SSH_ORIGINAL_COMMAND"); line != "" {
		if err := shell.Run(ctx, e, line); err != nil {
			return 1
		}
		return 0
	}
	if !tty {
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

// askCode reads the TOTP code: without echo on a terminal, else one line
// of standard input.
func askCode(fd int, tty bool) (string, error) {
	_, _ = fmt.Fprint(os.Stderr, "Authenticator code: ")
	if tty {
		b, err := term.ReadPassword(fd)
		_, _ = fmt.Fprintln(os.Stderr)
		return strings.TrimSpace(string(b)), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// rootShell relays the terminal to the root shell, raw, and follows its
// size.
func rootShell(fd int) func(ctx context.Context, socket, ticket string) error {
	return func(ctx context.Context, socket, ticket string) error {
		old, err := term.MakeRaw(fd)
		if err == nil {
			defer func() { _ = term.Restore(fd, old) }()
		}
		size := func() (uint16, uint16) {
			ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
			if err != nil {
				return 24, 80
			}
			return ws.Row, ws.Col
		}
		winch := make(chan os.Signal, 1)
		signal.Notify(winch, syscall.SIGWINCH)
		defer signal.Stop(winch)
		resize := make(chan struct{}, 1)
		go func() {
			for range winch {
				select {
				case resize <- struct{}{}:
				default:
				}
			}
		}()
		return shell.Relay(ctx, socket, ticket, os.Getenv("TERM"), os.Stdin, os.Stdout, size, resize)
	}
}
