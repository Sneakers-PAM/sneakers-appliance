// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package console_test

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/console"
)

// tty is one console: what init wrote to it, and what's typed on it.
type tty struct {
	mu     sync.Mutex
	wrote  strings.Builder
	typed  *io.PipeReader
	typing *io.PipeWriter
	broken bool
}

func newTTY() *tty {
	r, w := io.Pipe()
	return &tty{typed: r, typing: w}
}

func (t *tty) Read(p []byte) (int, error) { return t.typed.Read(p) }

func (t *tty) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.broken {
		return 0, errors.New("input/output error")
	}
	return t.wrote.Write(p)
}

func (t *tty) shows() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.wrote.String()
}

// waitShows waits until c shows want, and fails the test otherwise.
func waitShows(t *testing.T, name string, c *tty, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for c.shows() != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s shows %q, want %q", name, c.shows(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Every console shows what init writes: on VMware with no serial port the
// screen is tty0, on a headless box it's ttyS0, and both show the banner
// and the Secure Boot screen.
func TestEveryConsoleShowsTheOutput(t *testing.T) {
	vga, serial := newTTY(), newTTY()
	out, outW := io.Pipe()
	m := console.Join(out, io.Discard, []console.Console{{Name: "tty0", RW: vga}, {Name: "ttyS0", RW: serial}}, t.Logf)
	if _, err := io.WriteString(outW, "sneakers-init: phase=enrol protection=pending\n"); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]*tty{"tty0": vga, "ttyS0": serial} {
		waitShows(t, name, c, "sneakers-init: phase=enrol protection=pending\n")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !m.Idle() {
		if time.Now().After(deadline) {
			t.Fatal("everything is written but the mux isn't idle")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A console whose writes fail stops getting output; the others keep it.
func TestABrokenConsoleDoesNotStopTheOthers(t *testing.T) {
	vga, serial := newTTY(), newTTY()
	serial.broken = true
	out, outW := io.Pipe()
	console.Join(out, io.Discard, []console.Console{{Name: "ttyS0", RW: serial}, {Name: "tty0", RW: vga}}, t.Logf)
	if _, err := io.WriteString(outW, "one\n"); err != nil {
		t.Fatal(err)
	}
	waitShows(t, "tty0", vga, "one\n")
	if _, err := io.WriteString(outW, "two\n"); err != nil {
		t.Fatal(err)
	}
	waitShows(t, "tty0", vga, "one\ntwo\n")
}

// A console that never takes its output (a stuck serial line) doesn't hold
// up the screen.
func TestAStuckConsoleDoesNotHoldUpTheOthers(t *testing.T) {
	vga := newTTY()
	stuck := &blocked{}
	out, outW := io.Pipe()
	console.Join(out, io.Discard, []console.Console{{Name: "ttyS0", RW: stuck}, {Name: "tty0", RW: vga}}, t.Logf)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 2000; i++ {
			_, _ = io.WriteString(outW, "a line of boot output\n")
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("output stopped behind the stuck console")
	}
}

type blocked struct{}

func (*blocked) Read([]byte) (int, error)  { select {} }
func (*blocked) Write([]byte) (int, error) { select {} }

// What's typed on any console reaches init, so the Secure Boot choice can
// be answered on the screen or on the serial line.
func TestInputFromEitherConsoleReachesInit(t *testing.T) {
	vga, serial := newTTY(), newTTY()
	in, inW := io.Pipe()
	out, _ := io.Pipe()
	console.Join(out, inW, []console.Console{{Name: "tty0", RW: vga}, {Name: "ttyS0", RW: serial}}, t.Logf)
	lines := bufio.NewScanner(in)
	go func() { _, _ = io.WriteString(vga.typing, "no secure boot\n") }()
	if !lines.Scan() || lines.Text() != "no secure boot" {
		t.Fatalf("typed on tty0, init read %q", lines.Text())
	}
	go func() { _, _ = io.WriteString(serial.typing, "1\n") }()
	if !lines.Scan() || lines.Text() != "1" {
		t.Fatalf("typed on ttyS0, init read %q", lines.Text())
	}
}

func TestNamesReadsTheActiveList(t *testing.T) {
	got := console.Names("tty0 ttyS0\n")
	if strings.Join(got, ",") != "tty0,ttyS0" {
		t.Fatalf("Names = %q", got)
	}
	if got := console.Names("\n"); len(got) != 0 {
		t.Fatalf("Names of an empty list = %q", got)
	}
}
