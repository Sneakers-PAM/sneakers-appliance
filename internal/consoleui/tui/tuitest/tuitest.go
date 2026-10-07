// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package tuitest drives a console flow in tests: it types lines, ticks
// the clock and reads the screens drawn, and checks golden screens.
package tuitest

import (
	"context"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
)

var update = flag.Bool("update", false, "rewrite the golden screens")

// Golden compares p laid out on 80x24 with testdata/<name>.screen.
func Golden(t *testing.T, name string, p tui.Page) {
	t.Helper()
	got := p.Frame(80, 24).Text()
	path := filepath.Join("testdata", name+".screen")
	if *update {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path) // #nosec G304 -- a test's golden file
	if err != nil {
		t.Fatalf("%s: %v (run with -update to write it)", path, err)
	}
	if got != string(want) {
		t.Errorf("%s differs:\n--- got\n%s--- want\n%s", path, got, want)
	}
}

// Driver runs a flow on a fake console.
type Driver struct {
	UI     *tui.UI
	lines  chan string
	mu     sync.Mutex
	last   string
	frames chan string
	stop   chan struct{}
}

// New makes a console whose clock ticks every few milliseconds, so polling
// screens move on by themselves.
func New(t *testing.T) *Driver {
	d := &Driver{lines: make(chan string), frames: make(chan string, 4096), stop: make(chan struct{})}
	tick := make(chan time.Time)
	go func() {
		for {
			select {
			case <-d.stop:
				return
			case tick <- time.Now():
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()
	t.Cleanup(func() { close(d.stop) })
	d.UI = &tui.UI{Screen: tui.NewScreen(io.Discard, 80, 24, true), Lines: d.lines, Tick: tick, Cols: 80, Rows: 24,
		OnFrame: func(f tui.Frame) {
			d.mu.Lock()
			d.last = f.Text()
			d.mu.Unlock()
			select {
			case d.frames <- f.Text():
			default:
			}
		}}
	return d
}

// Expect waits until a screen shows want and returns it.
func (d *Driver) Expect(t *testing.T, want string) string {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case f := <-d.frames:
			if strings.Contains(f, want) {
				return f
			}
		case <-deadline:
			t.Fatalf("no screen showed %q; the last was:\n%s", want, d.Last())
		}
	}
}

// Last is the screen drawn last.
func (d *Driver) Last() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.last
}

// Type types a line, waiting until the flow reads it.
func (d *Driver) Type(t *testing.T, line string) {
	t.Helper()
	select {
	case d.lines <- line:
	case <-time.After(5 * time.Second):
		t.Fatalf("nothing read %q; the screen shows:\n%s", line, d.Last())
	}
}

// Run runs flow in the background and returns a channel with its result.
func Run(ctx context.Context, flow func(context.Context) error) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- flow(ctx) }()
	return ch
}
