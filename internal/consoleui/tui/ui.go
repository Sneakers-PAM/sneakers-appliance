// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"bufio"
	"context"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
)

// ErrClosed is Ask's error once the console's input has ended.
var ErrClosed = errors.New("tui: the console's input ended")

// UI is one console: the screen, the typed lines and a clock tick.
type UI struct {
	Screen *Screen
	Lines  <-chan string
	Tick   <-chan time.Time
	// Wake, when set, redraws the page at once, between ticks (the setup
	// code changed, say).
	Wake       <-chan struct{}
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
			clean, keep := Typed(l)
			if clean == l {
				u.Screen.Typed(len(l))
				return clean, true, nil
			}
			// The terminal moved the cursor for the key, or echoed it:
			// only a full redraw puts the screen right.
			u.Screen.Invalidate()
			if keep {
				return clean, true, nil
			}
			p, wake := view()
			if wake {
				return "", false, nil
			}
			u.Show(p)
		case <-u.Wake:
			p, wake := view()
			if wake {
				return "", false, nil
			}
			u.Show(p)
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

// keySequence is what a key other than a letter, a digit or Enter sends
// in line mode: a CSI sequence (the arrows, Home, End, Insert, Delete,
// the page keys and xterm's function keys, with any modifiers), the Linux
// VT's F1 to F5 (ESC [ [ A to E), an SS3 sequence (the arrows, Home, End
// and F1 to F4 in application mode, the keypad's Enter), and any other
// control character, Esc alone among them.
var keySequence = regexp.MustCompile(`\x1b\[\[[A-E]|\x1b\[[0-9;?]*[ -/]*[@-~]|\x1bO.|[\x00-\x1f\x7f]`)

// CleanLine is a typed line without the keys that aren't text: the
// consoles stay in line mode (raw key navigation is out of scope), so a
// cursor or function key arrives in the line as its escape sequence and
// does nothing. Esc alone leaves an empty line, which is Back.
func CleanLine(l string) string { return keySequence.ReplaceAllString(l, "") }

// Typed is a typed line as the console takes it: CleanLine's text, and
// whether to take it at all. A line of nothing but cursor or function keys
// is dropped, so an arrow and Enter never pick the default; Esc alone is
// taken, as an empty line.
func Typed(raw string) (string, bool) {
	clean := CleanLine(raw)
	if clean != raw && strings.TrimSpace(clean) == "" && strings.Trim(raw, "\x1b \t") != "" {
		return "", false
	}
	return clean, true
}

// IsBack reports whether a typed line means Back: Enter on an empty
// line, 0, b or back (Esc reads as an empty line).
func IsBack(l string) bool {
	switch strings.ToLower(strings.TrimSpace(l)) {
	case "", "0", "b", "back":
		return true
	}
	return false
}

// PlainOption on the kernel command line turns colour off on every
// console.
const PlainOption = "sneakers.console=plain"

// ColourWanted decides colour from the kernel command line and TERM.
func ColourWanted(cmdline, term string) bool {
	return term != "dumb" && !slices.Contains(strings.Fields(cmdline), PlainOption)
}
