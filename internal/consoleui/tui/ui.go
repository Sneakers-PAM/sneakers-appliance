// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"bufio"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"time"
)

// ErrClosed is Ask's error once the console's input has ended.
var ErrClosed = errors.New("tui: the console's input ended")

// UI is one console: the screen, the typed lines and a clock tick.
type UI struct {
	Screen     *Screen
	Lines      <-chan string
	Tick       <-chan time.Time
	Cols, Rows int
	// OnFrame, when set, sees every frame drawn (tests read the screen
	// with it).
	OnFrame func(Frame)
}

// Show draws p without waiting for anything.
func (u *UI) Show(p Page) {
	f := p.Frame(u.Cols, u.Rows)
	_ = u.Screen.Draw(f)
	if u.OnFrame != nil {
		u.OnFrame(f)
	}
}

// Ask draws view's page and waits for a typed line. On every tick it
// draws view's page again (only the rows that changed reach the screen);
// when view says to wake, Ask returns with ok false and no line.
func (u *UI) Ask(ctx context.Context, view func() (Page, bool)) (line string, ok bool, err error) {
	p, wake := view()
	if wake {
		return "", false, nil
	}
	u.Show(p)
	for {
		select {
		case <-ctx.Done():
			return "", false, ctx.Err()
		case l, open := <-u.Lines:
			if !open {
				return "", false, ErrClosed
			}
			u.Screen.Typed(len(l))
			return l, true, nil
		case <-u.Tick:
			p, wake := view()
			if wake {
				return "", false, nil
			}
			u.Show(p)
		}
	}
}

// Static wraps a fixed page as a view.
func Static(p Page) func() (Page, bool) { return func() (Page, bool) { return p, false } }

// ReadLines sends each line read from r, without its line ending, and
// closes the channel at the end of r.
func ReadLines(r io.Reader) <-chan string {
	ch := make(chan string)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 4096), 64*1024)
		for sc.Scan() {
			ch <- strings.TrimRight(sc.Text(), "\r")
		}
	}()
	return ch
}

// PlainOption on the kernel command line turns colour off on every
// console.
const PlainOption = "sneakers.console=plain"

// ColourWanted decides colour from the kernel command line and TERM.
func ColourWanted(cmdline, term string) bool {
	return term != "dumb" && !slices.Contains(strings.Fields(cmdline), PlainOption)
}
