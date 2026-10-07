// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tui_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
)

func page() tui.Page {
	return tui.Page{
		Title:  "Sneakers-PAM appliance",
		Right:  "sneakers.example.org",
		Banner: []tui.Line{tui.Styled(tui.Alert, "Protection: reduced (Secure Boot off).")},
		Body:   []tui.Line{tui.Text("Version  0.1.0"), tui.Text(""), tui.Text("Management  192.0.2.10")},
		Keys:   "Enter: menu",
		Prompt: "> ",
		Footer: "sneakers 0.1.0 | normal | 2026-10-07 18:03 UTC | NTP synced",
	}
}

// The page fills the rows it's given, and no row reaches the last column,
// so writing it can never scroll the screen.
func TestThePageFitsTheScreen(t *testing.T) {
	for _, size := range [][2]int{{80, 24}, {80, 25}, {132, 43}} {
		f := page().Frame(size[0], size[1])
		if len(f.Rows) != size[1] {
			t.Fatalf("%v: %d rows", size, len(f.Rows))
		}
		for i, r := range f.Rows {
			if n := r.Len(); n > size[0]-1 {
				t.Errorf("%v: row %d is %d wide", size, i, n)
			}
		}
		text := f.Text()
		for _, want := range []string{"Sneakers-PAM appliance", "sneakers.example.org", "Protection: reduced", "Management  192.0.2.10", "Enter: menu", "NTP synced"} {
			if !strings.Contains(text, want) {
				t.Errorf("%v: the frame lacks %q:\n%s", size, want, text)
			}
		}
		if f.CursorRow != size[1]-2 || f.CursorCol != 3 {
			t.Errorf("%v: cursor at %d,%d", size, f.CursorRow, f.CursorCol)
		}
	}
}

func TestALongBodyIsCutWithANote(t *testing.T) {
	p := page()
	for i := 0; i < 40; i++ {
		p.Body = append(p.Body, tui.Text("line"))
	}
	text := p.Frame(80, 24).Text()
	if !strings.Contains(text, "(more on a larger screen)") || !strings.Contains(text, "Enter: menu") {
		t.Fatalf("frame:\n%s", text)
	}
}

func TestWrap(t *testing.T) {
	got := tui.Wrap("Someone with the disk or SD card can change this box's software and read its data.", 30, "  ")
	want := []string{"  Someone with the disk or SD", "  card can change this box's", "  software and read its data."}
	if len(got) != len(want) {
		t.Fatalf("got %d lines: %q", len(got), got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("line %d: %q, want %q", i, got[i].String(), want[i])
		}
	}
}

// The first draw clears the screen; a later one rewrites only the rows
// that changed, keeping the typing position when the prompt stays put, so
// nothing flickers and a half-typed answer stays where it is.
func TestTheScreenRedrawsOnlyWhatChanged(t *testing.T) {
	var out bytes.Buffer
	s := tui.NewScreen(&out, 80, 24, false)
	p := page()
	if err := s.Draw(p.Frame(80, 24)); err != nil {
		t.Fatal(err)
	}
	first := out.String()
	if !strings.HasPrefix(first, "\x1b[0m\x1b[H\x1b[2J") || !strings.HasSuffix(first, "\x1b[23;4H") {
		t.Fatalf("first draw: %q", first)
	}
	out.Reset()
	if err := s.Draw(p.Frame(80, 24)); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("an unchanged frame wrote %q", out.String())
	}
	p.Footer = "sneakers 0.1.0 | normal | 2026-10-07 18:04 UTC | NTP synced"
	if err := s.Draw(p.Frame(80, 24)); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.HasPrefix(got, "\x1b7\x1b[24;1H") || !strings.HasSuffix(got, "\x1b[K\x1b8") || strings.Contains(got, "\x1b[2J") || strings.Contains(got, "Management") {
		t.Fatalf("the clock tick wrote %q", got)
	}
}

// A typed line is echoed by the terminal itself, so the prompt row is
// stale afterwards; a line too long for the row may have scrolled the
// screen, which only a full redraw puts right.
func TestTypingMakesThePromptRowStale(t *testing.T) {
	var out bytes.Buffer
	s := tui.NewScreen(&out, 80, 24, false)
	f := page().Frame(80, 24)
	_ = s.Draw(f)
	out.Reset()
	s.Typed(len("yes"))
	_ = s.Draw(f)
	if got := out.String(); !strings.Contains(got, "\x1b[23;1H") || strings.Contains(got, "\x1b[2J") {
		t.Fatalf("after a short line: %q", got)
	}
	out.Reset()
	s.Typed(200)
	_ = s.Draw(f)
	if got := out.String(); !strings.Contains(got, "\x1b[2J") {
		t.Fatalf("after a long line: %q", got)
	}
}

// Colour is foreground SGR only (no backgrounds or reverse video, which
// would break the screen reader and look wrong on a plain console); plain
// mode writes none.
func TestColourAndPlain(t *testing.T) {
	for _, color := range []bool{true, false} {
		var out bytes.Buffer
		s := tui.NewScreen(&out, 80, 24, color)
		_ = s.Draw(page().Frame(80, 24))
		got := out.String()
		hasColour := strings.Contains(got, "\x1b[1;31m")
		if hasColour != color {
			t.Errorf("color=%v: wrote alert colour %v: %q", color, hasColour, got)
		}
		for _, bad := range []string{"\x1b[7m", "\x1b[4", "\x1b[10"} {
			if strings.Contains(got, bad) {
				t.Errorf("color=%v: wrote %q", color, bad)
			}
		}
	}
}

func TestColourWanted(t *testing.T) {
	cases := []struct {
		cmdline, term string
		want          bool
	}{
		{"console=tty0 console=ttyS0", "", true},
		{"quiet sneakers.console=plain", "", false},
		{"", "dumb", false},
	}
	for _, c := range cases {
		if got := tui.ColourWanted(c.cmdline, c.term); got != c.want {
			t.Errorf("%q %q: %v", c.cmdline, c.term, got)
		}
	}
}

// Ask draws the page, redraws it on every tick, and returns the typed
// line; a view that says to wake ends the wait without a line.
func TestAsk(t *testing.T) {
	lines := make(chan string, 1)
	tick := make(chan time.Time)
	var frames []string
	u := &tui.UI{Screen: tui.NewScreen(&bytes.Buffer{}, 80, 24, false), Lines: lines, Tick: tick, Cols: 80, Rows: 24,
		OnFrame: func(f tui.Frame) { frames = append(frames, f.Text()) }}
	n := 0
	view := func() (tui.Page, bool) {
		n++
		p := page()
		p.Body = []tui.Line{tui.Text(strings.Repeat("x", n))}
		return p, n == 3
	}
	done := make(chan struct{})
	var line string
	var ok bool
	go func() {
		defer close(done)
		line, ok, _ = u.Ask(context.Background(), view)
	}()
	tick <- time.Now()
	tick <- time.Now()
	<-done
	if ok || line != "" || len(frames) != 2 || !strings.Contains(frames[1], "xx") {
		t.Fatalf("woken: %q %v, %d frames", line, ok, len(frames))
	}
	lines <- "yes"
	line, ok, err := u.Ask(context.Background(), func() (tui.Page, bool) { return page(), false })
	if err != nil || !ok || line != "yes" {
		t.Fatalf("typed: %q %v %v", line, ok, err)
	}
}

func TestAskEndsWhenTheConsoleCloses(t *testing.T) {
	lines := make(chan string)
	close(lines)
	u := &tui.UI{Screen: tui.NewScreen(&bytes.Buffer{}, 80, 24, false), Lines: lines, Cols: 80, Rows: 24}
	if _, _, err := u.Ask(context.Background(), func() (tui.Page, bool) { return page(), false }); err != tui.ErrClosed {
		t.Fatalf("err = %v", err)
	}
}

func TestReadLines(t *testing.T) {
	ch := tui.ReadLines(strings.NewReader("no secure boot\r\n1\nlast"))
	var got []string
	for l := range ch {
		got = append(got, l)
	}
	if strings.Join(got, "|") != "no secure boot|1|last" {
		t.Fatalf("lines %q", got)
	}
}
