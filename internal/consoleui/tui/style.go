// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package tui draws the console's full-screen pages: a fixed layout that
// fits an 80x24 terminal, written with cursor addressing and redrawn row
// by row so nothing flickers, in colour where wanted and plain otherwise.
// Input is line by line: the consoles stay in the kernel's line mode
// (init joins them through pipes), which works the same on the screen and
// on a serial line.
package tui

import (
	"strings"
	"unicode/utf8"
)

// Style is how a span is shown. Colour is foreground only, so a console
// without colour, or one that drops it, still shows the same text.
type Style uint8

// The styles.
const (
	Normal Style = iota
	Bold
	OK
	Warn
	Alert
	Title
)

var sgr = map[Style]string{Bold: "1", OK: "32", Warn: "1;33", Alert: "1;31", Title: "1;36"}

// Span is text in one style.
type Span struct {
	Text  string
	Style Style
}

// Line is one row's spans.
type Line []Span

// Text is a line of plain text.
func Text(s string) Line { return Line{{Text: s}} }

// Styled is a line of text in one style.
func Styled(st Style, s string) Line { return Line{{Text: s, Style: st}} }

// String is the line's text without styles.
func (l Line) String() string {
	var b strings.Builder
	for _, s := range l {
		b.WriteString(s.Text)
	}
	return b.String()
}

// Len is the line's width in characters.
func (l Line) Len() int { return utf8.RuneCountInString(l.String()) }

// cut keeps the first n characters.
func (l Line) cut(n int) Line {
	var out Line
	for _, s := range l {
		if n <= 0 {
			break
		}
		r := []rune(s.Text)
		if len(r) > n {
			r = r[:n]
		}
		out = append(out, Span{Text: string(r), Style: s.Style})
		n -= len(r)
	}
	return out
}

func (l Line) encode(color bool) string {
	var b strings.Builder
	for _, s := range l {
		if code := sgr[s.Style]; color && code != "" && s.Text != "" {
			b.WriteString("\x1b[" + code + "m" + s.Text + "\x1b[0m")
			continue
		}
		b.WriteString(s.Text)
	}
	return b.String()
}

// Wrap breaks text into lines of at most width characters, each starting
// with indent. A word longer than a line is cut.
func Wrap(text string, width int, indent string) []Line {
	return WrapStyled(Normal, text, width, indent)
}

// WrapStyled is Wrap in one style.
func WrapStyled(st Style, text string, width int, indent string) []Line {
	room := width - utf8.RuneCountInString(indent)
	if room < 10 {
		room = 10
	}
	var out []Line
	cur := ""
	flush := func() {
		out = append(out, Line{{Text: indent}, {Text: cur, Style: st}})
		cur = ""
	}
	for _, w := range strings.Fields(text) {
		for utf8.RuneCountInString(w) > room {
			if cur != "" {
				flush()
			}
			r := []rune(w)
			cur = string(r[:room])
			flush()
			w = string(r[room:])
		}
		switch {
		case cur == "":
			cur = w
		case utf8.RuneCountInString(cur)+1+utf8.RuneCountInString(w) <= room:
			cur += " " + w
		default:
			flush()
			cur = w
		}
	}
	if cur != "" || len(out) == 0 {
		flush()
	}
	return out
}
