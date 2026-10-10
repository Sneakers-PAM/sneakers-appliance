// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

// openPTY opens a pseudo-terminal pair, as sshd gives the shell one.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no /dev/ptmx:", err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	s, err := os.OpenFile(filepath.Join("/dev/pts", strconv.Itoa(n)), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close(); _ = s.Close() })
	return m, s
}

// screen collects what the shell writes to the terminal.
type screen struct {
	t    *testing.T
	m    *os.File
	got  chan string
	all  strings.Builder
	mark int
}

func (s *screen) read() {
	b := make([]byte, 4096)
	for {
		n, err := s.m.Read(b)
		if n > 0 {
			s.got <- string(b[:n])
		}
		if err != nil {
			close(s.got)
			return
		}
	}
}

// waitFor reads until the screen after the last match holds want, and
// returns that part up to the end of want.
func (s *screen) waitFor(want string) string {
	s.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		rest := s.all.String()[s.mark:]
		if i := strings.Index(rest, want); i >= 0 {
			s.mark += i + len(want)
			return rest[:i+len(want)]
		}
		select {
		case chunk, ok := <-s.got:
			if !ok {
				s.t.Fatalf("the terminal closed before %q:\n%q", want, rest)
			}
			s.all.WriteString(chunk)
		case <-deadline:
			s.t.Fatalf("no %q on the terminal:\n%q", want, rest)
		}
	}
}

func (s *screen) send(keys string) {
	s.t.Helper()
	if _, err := s.m.WriteString(keys); err != nil {
		s.t.Fatal(err)
	}
}

// Over a real terminal, as an SSH client drives it: Tab completes
// "snea" to "sneakers ", a second Tab lists what can follow, and an
// admin who isn't an owner isn't offered the owner's commands.
func TestTabCompletionOnATerminal(t *testing.T) {
	m, s := openPTY(t)
	old, err := term.MakeRaw(int(s.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = term.Restore(int(s.Fd()), old) }()
	sc := &screen{t: t, m: m, got: make(chan string, 64)}
	go sc.read()
	e := &shell.Env{Origin: shell.OriginSSH, Backend: &recordingBackend{}, Product: sneakers, Role: "admin",
		Values: []shell.Value{{Name: "setup-token", Label: "Sneakers setup token"}}}
	done := make(chan error, 1)
	go func() { done <- shell.Interactive(context.Background(), e, s, "bob@box1> ") }()
	sc.waitFor("bob@box1> ")

	sc.send("snea\t")
	sc.waitFor("sneakers ")
	sc.send("\t\t")
	listed := sc.waitFor("setup-token")
	if !strings.Contains(listed, "mcp") {
		t.Errorf("a second Tab doesn't list both commands:\n%q", listed)
	}
	sc.waitFor("bob@box1> sneakers ")
	// network set and network confirm are an owner's: for an admin the
	// only network command over SSH is show, so Tab completes it.
	sc.send("\x15network \t")
	sc.waitFor("network show ")
	sc.send("\x15exit\r")
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exit didn't end the session")
	}
}
