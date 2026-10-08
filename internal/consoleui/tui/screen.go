// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

// stale marks a row whose content on the screen isn't what was drawn (the
// terminal echoed a typed line onto it).
const stale = "\x00"

// Screen writes frames to a terminal: the first one after a clear, then
// only the rows that changed, each in one write.
type Screen struct {
	w          io.Writer
	color      bool
	cols, rows int

	mu          sync.Mutex
	drawn       bool
	prev        []string
	cursor      [2]int
	cursorStale bool
	shown       bool
}

// NewScreen draws on w, a cols x rows terminal.
func NewScreen(w io.Writer, cols, rows int, color bool) *Screen {
	return &Screen{w: w, color: color, cols: cols, rows: rows}
}

// Invalidate makes the next Draw a full one.
func (s *Screen) Invalidate() {
	s.mu.Lock()
	s.drawn = false
	s.mu.Unlock()
}

// Typed tells the screen a line of n characters was typed at the prompt:
// the terminal echoed it there and moved the cursor. A line too long for
// the row may have scrolled the screen, so the next Draw is a full one.
func (s *Screen) Typed(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cursor[1]+n >= s.cols-1 {
		s.drawn = false
		return
	}
	for _, r := range []int{s.cursor[0], s.cursor[0] + 1} {
		if r < len(s.prev) {
			s.prev[r] = stale
		}
	}
	s.cursorStale = true
}

// Draw shows f.
func (s *Screen) Draw(f Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]string, len(f.Rows))
	for i, r := range f.Rows {
		rows[i] = r.encode(s.color)
	}
	cursor := [2]int{f.CursorRow, f.CursorCol}
	var b strings.Builder
	if !s.drawn || len(s.prev) != len(rows) {
		b.WriteString("\x1b[0m\x1b[H\x1b[2J")
		for i, r := range rows {
			if r != "" {
				fmt.Fprintf(&b, "\x1b[%d;1H%s", i+1, r)
			}
		}
		fmt.Fprintf(&b, "\x1b[%d;%dH%s", cursor[0]+1, cursor[1]+1, visibility(f.Cursor))
	} else {
		moved := cursor != s.cursor || s.cursorStale
		for i, r := range rows {
			if r != s.prev[i] {
				// Every row is the full width, so it overwrites the old
				// one entirely; an erase to the end of the line would clear
				// the frame's right edge from the last column.
				fmt.Fprintf(&b, "\x1b[%d;1H%s", i+1, r)
			}
		}
		switch {
		case moved || f.Cursor != s.shown:
			fmt.Fprintf(&b, "\x1b[%d;%dH%s", cursor[0]+1, cursor[1]+1, visibility(f.Cursor))
		case b.Len() > 0:
			// Keep the typing position: an answer typed half-way stays.
			b.WriteString("\x1b8")
			out := "\x1b7" + b.String()
			b.Reset()
			b.WriteString(out)
		}
	}
	s.prev, s.cursor, s.drawn, s.cursorStale, s.shown = rows, cursor, true, false, f.Cursor
	if b.Len() == 0 {
		return nil
	}
	_, err := io.WriteString(s.w, b.String())
	return err
}

// visibility shows the cursor where there's something to type, and hides
// it on a page that only shows.
func visibility(shown bool) string {
	if shown {
		return "\x1b[?25h"
	}
	return "\x1b[?25l"
}
