// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package tuitest drives a console flow in tests: it types lines, ticks
// the clock and reads the screens drawn, and checks golden screens.
package tuitest

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
)

var update = flag.Bool("update", false, "rewrite the golden screens")

// Sizes are the screens every golden is checked at: the large font on a
// 1024x768 screen, and the classic 80x24.
var Sizes = [][2]int{{64, 24}, {80, 24}}

// Golden compares p with its golden screens in testdata: laid out plain
// at every size in Sizes (<name>.<cols>x<rows>.screen), and in colour at
// the large font's size (<name>.colour.screen).
func Golden(t *testing.T, name string, p tui.Page) {
	t.Helper()
	for _, sz := range Sizes {
		f := p.Frame(sz[0], sz[1])
		aligned(t, fmt.Sprintf("%s at %dx%d", name, sz[0], sz[1]), f.Text(), sz[0])
		aligned(t, fmt.Sprintf("%s at %dx%d in colour", name, sz[0], sz[1]), f.Coloured(), sz[0])
		compare(t, fmt.Sprintf("%s.%dx%d.screen", name, sz[0], sz[1]), f.Text())
	}
	compare(t, name+".colour.screen", p.Frame(Sizes[0][0], Sizes[0][1]).Coloured())
}

var sgrCode = regexp.MustCompile(`\\e\[[0-9;]*m`)

// aligned checks every row of a frame ends in the same column: width
// visible characters, the colour codes not counted. The plain form has
// its trailing blanks trimmed, but the frame's right edge isn't blank.
func aligned(t *testing.T, what, frame string, width int) {
	t.Helper()
	for i, row := range strings.Split(strings.TrimSuffix(frame, "\n"), "\n") {
		if n := utf8.RuneCountInString(sgrCode.ReplaceAllString(row, "")); n != width {
			t.Errorf("%s: row %d is %d wide, not %d: %q", what, i, n, width, row)
		}
	}
}

func compare(t *testing.T, file, got string) {
	t.Helper()
	path := filepath.Join("testdata", file)
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
	d.UI = &tui.UI{Screen: tui.NewScreen(io.Discard, 64, 24, true), Lines: d.lines, Tick: tick, Cols: 64, Rows: 24,
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
