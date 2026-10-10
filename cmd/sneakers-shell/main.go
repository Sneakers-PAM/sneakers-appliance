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
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productinfo"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

// The local sockets: init's power socket for reboot and poweroff.
const powerSocket = "/run/sneakers/power.sock"

func unixClient(sock string, timeout time.Duration) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}, Timeout: timeout}
}

// accessTimeout is how long a call to accessd may take: as long as
// :8443's front waits, since a switch answers once the product is ready
// with it (osadmin.DefaultSwitchReadyBound).
const accessTimeout = 2 * time.Minute

func backend() *shell.Services {
	name := "unknown"
	if u, err := user.LookupId(strconv.Itoa(os.Getuid())); err == nil {
		name = u.Username
	}
	sess, err := shell.SessionFromSSH(os.Getenv, name)
	s := &shell.Services{
		Session: sess, SessionErr: err,
		Power:      initv1connect.NewPowerServiceClient(unixClient(powerSocket, 30*time.Second), "http://power.sock"),
		StatusFile: accessapi.StatusFile,
	}
	s.UseAccessd(unixClient(accessapi.SocketPath, accessTimeout), "http://access.sock")
	return s
}

func main() { os.Exit(run()) }

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	b := backend()
	fd := int(os.Stdin.Fd()) // #nosec G115 -- a file descriptor fits an int
	tty := term.IsTerminal(fd)
	stdin := newStdinLines(os.Stdin)
	code, err := askCode(fd, tty, stdin)
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
	e := &shell.Env{Origin: shell.OriginSSH, Backend: b, In: stdin, Out: os.Stdout, Err: os.Stderr,
		Product: productinfo.Installed(productinfo.Dir), Role: b.Role}
	if e.Product.Present() {
		// The values the bundle exposes to this login's role; accessd
		// checks the role again on every read.
		if spec, err := productspec.Load(filepath.Join(productinfo.Dir, "current")); err == nil {
			e.Values = shell.ValuesFor(spec, b.Role)
			// The switches it declares, so mcp's help and completion offer
			// only those.
			e.Switches = make([]string, 0, len(spec.Switches))
			for _, w := range spec.Switches {
				e.Switches = append(e.Switches, w.Name)
			}
		}
	}
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
func askCode(fd int, tty bool, stdin *stdinLines) (string, error) {
	_, _ = fmt.Fprint(os.Stderr, "Authenticator code: ")
	if tty {
		b, err := term.ReadPassword(fd)
		_, _ = fmt.Fprintln(os.Stderr)
		return strings.TrimSpace(string(b)), err
	}
	return stdin.line()
}

// stdinLines is standard input without a terminal. line reads up to CR or
// LF: a client whose own terminal is raw sends Enter as a bare CR, and
// with no terminal on the box nothing turns it into LF. It reads a byte at
// a time, so what follows the line is left for the command, and the LF of
// a CRLF is dropped.
type stdinLines struct {
	r      io.Reader
	skipLF bool
}

func newStdinLines(r io.Reader) *stdinLines { return &stdinLines{r: r} }

func (s *stdinLines) line() (string, error) {
	var b []byte
	var one [1]byte
	for {
		n, err := s.Read(one[:])
		if n == 1 {
			switch one[0] {
			case '\r':
				s.skipLF = true
				return strings.TrimSpace(string(b)), nil
			case '\n':
				return strings.TrimSpace(string(b)), nil
			}
			b = append(b, one[0])
			continue
		}
		if err != nil {
			if len(b) > 0 {
				return strings.TrimSpace(string(b)), nil
			}
			return "", err
		}
	}
}

func (s *stdinLines) Read(p []byte) (int, error) {
	for {
		n, err := s.r.Read(p)
		if s.skipLF && n > 0 {
			s.skipLF = false
			if p[0] == '\n' {
				n = copy(p, p[1:n])
				if n == 0 && err == nil {
					continue
				}
			}
		}
		return n, err
	}
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
