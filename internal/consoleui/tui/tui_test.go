// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tui_test

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
)

func page() tui.Page {
	return tui.Page{
		Name:    "Sneakers-PAM appliance",
		Version: "0.1.0",
		Info:    "slot A  1 node",
		Body:    []tui.Line{tui.Styled(tui.Alert, "Protection reduced"), tui.Text(""), tui.Text("Address  192.0.2.10")},
		Keys:    tui.Line{{Text: "R", Style: tui.Strong}, {Text: "  Recover access"}},
		Prompt:  "> ",
	}
}

// The frame fills the terminal it's given, every row the same width; the
// body block is centred in it.
func TestTheFrameFitsTheTerminal(t *testing.T) {
	for _, size := range [][2]int{{64, 24}, {80, 24}, {80, 25}, {128, 48}} {
		f := page().Frame(size[0], size[1])
		if len(f.Rows) != size[1] {
			t.Fatalf("%v: %d rows", size, len(f.Rows))
		}
		for i, r := range f.Rows {
			if n := r.Len(); n != size[0] {
				t.Errorf("%v: row %d is %d wide, want %d", size, i, n, size[0])
			}
		}
		rows := strings.Split(strings.TrimSuffix(f.Text(), "\n"), "\n")
		if !strings.HasPrefix(rows[0], "+--") || !strings.HasPrefix(rows[size[1]-1], "+--") {
			t.Errorf("%v: no top and bottom border:\n%s", size, f.Text())
		}
		for i := 1; i < size[1]-1; i++ {
			bars := strings.HasPrefix(rows[i], "|") && strings.HasSuffix(rows[i], "|")
			rule := strings.HasPrefix(rows[i], "+") && strings.HasSuffix(rows[i], "+")
			if !bars && !rule {
				t.Errorf("%v: row %d has no side bars: %q", size, i, rows[i])
			}
		}
		text := f.Text()
		for _, want := range []string{"Sneakers-PAM appliance", "0.1.0", "slot A  1 node", "Protection reduced", "Address  192.0.2.10", "R  Recover access"} {
			if !strings.Contains(text, want) {
				t.Errorf("%v: the frame lacks %q:\n%s", size, want, text)
			}
		}
		// The block is centred: the body starts as far from the left bar
		// as the widest block line ends from the right one, give or take one.
		var body string
		for _, r := range rows {
			if strings.Contains(r, "Address  192.0.2.10") {
				body = r
			}
		}
		left := strings.Index(body, "Address") - 1
		right := len(body) - 1 - (left + 1 + tui.BlockWidth(size[0]))
		if d := left - right; d < -1 || d > 1 || tui.BlockWidth(size[0]) > tui.Width {
			t.Errorf("%v: the block isn't centred: left %d right %d (block %d)", size, left, right, tui.BlockWidth(size[0]))
		}
		if !f.Cursor || f.CursorRow >= size[1]-1 || f.CursorCol != left+1+2 {
			t.Errorf("%v: cursor %v at %d,%d", size, f.Cursor, f.CursorRow, f.CursorCol)
		}
	}
}

// The block is never wider than the large font's 64 columns allow.
func TestTheBlockFitsTheLargeFont(t *testing.T) {
	if got := tui.BlockWidth(64); got != tui.Width || tui.Width+2+2 > 64 {
		t.Fatalf("block %d at 64 columns, Width %d", got, tui.Width)
	}
	if got := tui.BlockWidth(40); got > 40-2-2 {
		t.Fatalf("block %d at 40 columns", got)
	}
}

// The boot and info screens carry the mark and the wordmark, centred
// above the body; the others a one-row header.
func TestTheMarkIsOnTheBigPagesOnly(t *testing.T) {
	p := page()
	p.Big = true
	big := p.Frame(64, 24).Text()
	for _, want := range tui.MarkLines() {
		if !strings.Contains(big, want) {
			t.Fatalf("the big page lacks the mark line %q:\n%s", want, big)
		}
	}
	small := page().Frame(64, 24).Text()
	if strings.Contains(small, tui.MarkLines()[0]) {
		t.Fatalf("the small page has the mark:\n%s", small)
	}
}

// On the big pages the version has a dim line of its own, centred under
// the name.
func TestTheVersionIsUnderTheNameOnTheBigPages(t *testing.T) {
	p := page()
	p.Name = "Sneakers-PAM Appliance"
	p.Big = true
	f := p.Frame(64, 24)
	name, version := -1, -1
	for i, r := range f.Rows {
		switch strings.TrimSpace(strings.Trim(r.String(), "|")) {
		case "Sneakers-PAM Appliance":
			name = i
		case "0.1.0":
			version = i
			for _, s := range r {
				if s.Text == "0.1.0" && s.Style != tui.Dim {
					t.Errorf("the version is in style %d, not dim", s.Style)
				}
			}
		}
	}
	if name < 0 || version != name+1 {
		t.Fatalf("the name is on row %d and the version on row %d:\n%s", name, version, f.Text())
	}
	row := func(i int) string { return f.Rows[i].String() }
	centre := func(s, what string) int { i := strings.Index(s, what); return i + len(what)/2 }
	if d := centre(row(name), "Sneakers-PAM Appliance") - centre(row(version), "0.1.0"); d < -1 || d > 1 {
		t.Fatalf("the version isn't centred under the name:\n%s", f.Text())
	}
}

// Short of room, a one-row-header page gives up the blank under the
// header before it cuts the body.
func TestAFullBodyMovesUpBeforeItIsCut(t *testing.T) {
	p := page()
	p.Body = nil
	// 24 rows: the borders, the header and its rule, the prompt, the keys
	// and their rule leave 17.
	for i := 0; i < 17; i++ {
		p.Body = append(p.Body, tui.Text(fmt.Sprintf("line %d", i)))
	}
	text := p.Frame(64, 24).Text()
	if strings.Contains(text, "...") || !strings.Contains(text, "line 0") || !strings.Contains(text, "line 16") {
		t.Fatalf("frame:\n%s", text)
	}
}

// Still short of room, the body's blank rows go before any line is cut.
func TestBlankRowsGoBeforeTheBodyIsCut(t *testing.T) {
	p := page()
	p.Body = nil
	for i := 0; i < 17; i++ {
		p.Body = append(p.Body, tui.Text(fmt.Sprintf("line %d", i)))
		if i == 3 || i == 9 {
			p.Body = append(p.Body, tui.Text(""))
		}
	}
	text := p.Frame(64, 24).Text()
	if strings.Contains(text, "...") || !strings.Contains(text, "line 0") || !strings.Contains(text, "line 16") {
		t.Fatalf("frame:\n%s", text)
	}
}

func TestALongBodyIsCutWithANote(t *testing.T) {
	p := page()
	for i := 0; i < 40; i++ {
		p.Body = append(p.Body, tui.Text("line"))
	}
	text := p.Frame(64, 24).Text()
	if !strings.Contains(text, "...") || !strings.Contains(text, "R  Recover access") {
		t.Fatalf("frame:\n%s", text)
	}
}

// A page with nothing to type hides the cursor; with keys but no prompt
// the cursor waits after the keys.
func TestKeysWithoutAPromptTakeTheCursor(t *testing.T) {
	p := page()
	p.Prompt = ""
	f := p.Frame(64, 24)
	row := f.Rows[f.CursorRow].String()
	if !f.Cursor || !strings.Contains(row, "R  Recover access") || f.CursorCol != strings.Index(row, "access")+len("access")+3 {
		t.Fatalf("cursor %v at %d,%d on %q", f.Cursor, f.CursorRow, f.CursorCol, row)
	}
}

func TestNoPromptHidesTheCursor(t *testing.T) {
	p := page()
	p.Prompt, p.Keys = "", nil
	if f := p.Frame(64, 24); f.Cursor {
		t.Fatalf("cursor shown at %d,%d", f.CursorRow, f.CursorCol)
	}
	var out bytes.Buffer
	s := tui.NewScreen(&out, 64, 24, false)
	_ = s.Draw(p.Frame(64, 24))
	if !strings.Contains(out.String(), "\x1b[?25l") {
		t.Fatalf("the cursor wasn't hidden: %q", out.String())
	}
	out.Reset()
	_ = s.Draw(page().Frame(64, 24))
	if !strings.Contains(out.String(), "\x1b[?25h") {
		t.Fatalf("the cursor wasn't shown again: %q", out.String())
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
	s := tui.NewScreen(&out, 64, 24, false)
	p := page()
	f := p.Frame(64, 24)
	if err := s.Draw(f); err != nil {
		t.Fatal(err)
	}
	first := out.String()
	if !strings.HasPrefix(first, "\x1b[0m\x1b[H\x1b[2J") || !strings.HasSuffix(first, fmt.Sprintf("\x1b[%d;%dH\x1b[?25h", f.CursorRow+1, f.CursorCol+1)) {
		t.Fatalf("first draw: %q", first)
	}
	out.Reset()
	if err := s.Draw(p.Frame(64, 24)); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("an unchanged frame wrote %q", out.String())
	}
	p.Body[2] = tui.Text("Address  192.0.2.11")
	if err := s.Draw(p.Frame(64, 24)); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.HasPrefix(got, "\x1b7\x1b[") || !strings.HasSuffix(got, "\x1b8") || strings.Contains(got, "\x1b[2J") || strings.Contains(got, "Protection") || !strings.Contains(got, "192.0.2.11") {
		t.Fatalf("the change wrote %q", got)
	}
}

// A typed line is echoed by the terminal itself, so the prompt row is
// stale afterwards; a line too long for the row may have scrolled the
// screen, which only a full redraw puts right.
func TestTypingMakesThePromptRowStale(t *testing.T) {
	var out bytes.Buffer
	s := tui.NewScreen(&out, 64, 24, false)
	f := page().Frame(64, 24)
	_ = s.Draw(f)
	out.Reset()
	s.Typed(len("yes"))
	_ = s.Draw(f)
	if got := out.String(); !strings.Contains(got, fmt.Sprintf("\x1b[%d;1H", f.CursorRow+1)) || strings.Contains(got, "\x1b[2J") {
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
		for _, m := range sgrCodes.FindAllStringSubmatch(got, -1) {
			for _, code := range strings.Split(m[1], ";") {
				if code == "7" || code == "4" || len(code) == 2 && code[0] == '4' || len(code) == 3 && code[:2] == "10" {
					t.Errorf("color=%v: wrote SGR %q", color, m[0])
				}
			}
		}
	}
}

var sgrCodes = regexp.MustCompile(`\x1b\[([0-9;]*)m`)

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

// A wake redraws the page between ticks.
func TestWakeRedraws(t *testing.T) {
	wake := make(chan struct{})
	lines := make(chan string)
	drawn := make(chan string, 4)
	u := &tui.UI{Screen: tui.NewScreen(&bytes.Buffer{}, 64, 24, false), Lines: lines, Wake: wake, Cols: 64, Rows: 24,
		OnFrame: func(f tui.Frame) { drawn <- f.Text() }}
	n := 0
	go func() {
		_, _, _ = u.Ask(context.Background(), func() (tui.Page, bool) {
			n++
			p := page()
			p.Body = []tui.Line{tui.Text(fmt.Sprintf("draw %d", n))}
			return p, false
		})
	}()
	<-drawn
	wake <- struct{}{}
	if f := <-drawn; !strings.Contains(f, "draw 2") {
		t.Fatalf("after the wake:\n%s", f)
	}
}

// The consoles stay in line mode, so a cursor or function key arrives
// inside the typed line as its escape sequence. Every key a PC keyboard
// sends on the Linux VT, xterm or a serial terminal reads as nothing; Esc
// alone reads as an empty line (Back), and the text around a key stays.
func TestKeysReadAsNothing(t *testing.T) {
	keys := map[string]string{
		"up": "\x1b[A", "down": "\x1b[B", "right": "\x1b[C", "left": "\x1b[D",
		"up (application mode)": "\x1bOA", "right (application mode)": "\x1bOC",
		"home": "\x1b[H", "end": "\x1b[F", "home (VT)": "\x1b[1~", "end (VT)": "\x1b[4~",
		"home (rxvt)": "\x1b[7~", "end (rxvt)": "\x1b[8~", "home (application mode)": "\x1bOH", "end (application mode)": "\x1bOF",
		"insert": "\x1b[2~", "delete": "\x1b[3~", "page up": "\x1b[5~", "page down": "\x1b[6~",
		"F1 (VT)": "\x1b[[A", "F5 (VT)": "\x1b[[E", "F1 (xterm)": "\x1bOP", "F5 (xterm)": "\x1b[15~", "F12": "\x1b[24~",
		"shift+up": "\x1b[1;2A", "ctrl+right": "\x1b[1;5C", "keypad Enter": "\x1bOM",
		"Esc": "\x1b", "tab": "\t", "ctrl+a": "\x01",
	}
	for name, seq := range keys {
		if got := tui.CleanLine(seq); got != "" {
			t.Errorf("%s (%q) reads as %q", name, seq, got)
		}
		if got := tui.CleanLine("1" + seq + seq); got != "1" {
			t.Errorf("1 then %s twice reads as %q", name, got)
		}
		if got := tui.CleanLine(seq + "no secure boot"); got != "no secure boot" {
			t.Errorf("%s then text reads as %q", name, got)
		}
	}
	if got := tui.CleanLine("no secure boot"); got != "no secure boot" {
		t.Errorf("plain text reads as %q", got)
	}
}

// Back is Enter on an empty line, or 0, b or back, in any case and with
// blanks round it; Esc reads as an empty line.
func TestIsBack(t *testing.T) {
	for _, l := range []string{"", "  ", "0", "b", "B", "back", " Back ", tui.CleanLine("\x1b")} {
		if !tui.IsBack(l) {
			t.Errorf("%q isn't Back", l)
		}
	}
	for _, l := range []string{"1", "2", "k", "backup", "00"} {
		if tui.IsBack(l) {
			t.Errorf("%q is Back", l)
		}
	}
}

// Ask hands on the typed line without its escape sequences, and a line
// that had one redraws the whole screen: the terminal may have moved the
// cursor or echoed the key.
func TestAskCleansTheLineAndRedraws(t *testing.T) {
	lines := make(chan string, 1)
	var out bytes.Buffer
	u := &tui.UI{Screen: tui.NewScreen(&out, 80, 24, false), Lines: lines, Cols: 80, Rows: 24}
	view := func() (tui.Page, bool) { return page(), false }
	lines <- "1\x1b[C"
	line, ok, err := u.Ask(context.Background(), view)
	if err != nil || !ok || line != "1" {
		t.Fatalf("typed: %q %v %v", line, ok, err)
	}
	out.Reset()
	u.Show(page())
	if !strings.Contains(out.String(), "\x1b[2J") {
		t.Fatalf("the screen wasn't drawn again in full: %q", out.String())
	}
}

// A line of nothing but cursor or function keys is dropped: Ask redraws
// and waits on, so an arrow and Enter never pick the default. Esc alone
// is an empty line.
func TestAskDropsALineOfOnlyKeys(t *testing.T) {
	lines := make(chan string, 3)
	u := &tui.UI{Screen: tui.NewScreen(&bytes.Buffer{}, 80, 24, false), Lines: lines, Cols: 80, Rows: 24}
	view := func() (tui.Page, bool) { return page(), false }
	lines <- "\x1b[A"
	lines <- "\x1b[1~\x1bOP"
	lines <- "2"
	if line, ok, err := u.Ask(context.Background(), view); err != nil || !ok || line != "2" {
		t.Fatalf("typed: %q %v %v", line, ok, err)
	}
	lines <- "\x1b"
	if line, ok, err := u.Ask(context.Background(), view); err != nil || !ok || line != "" {
		t.Fatalf("Esc: %q %v %v", line, ok, err)
	}
	for raw, want := range map[string]bool{"\x1b[C": false, "\x1b": true, "": true, "1\x1b[C": true, "\x1b[A\x1b[B": false} {
		if _, keep := tui.Typed(raw); keep != want {
			t.Errorf("Typed(%q) keeps %v", raw, keep)
		}
	}
}
