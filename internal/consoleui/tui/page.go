// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"
	"unicode/utf8"
)

// Page is one full-screen state: a header, an optional banner (reduced
// protection, warnings that must not scroll away), the body, the keys
// that work here, the prompt line, and the footer.
type Page struct {
	Title  string
	Right  string
	Banner []Line
	Body   []Line
	Keys   string
	// Prompt is the text before the typing position; the cursor waits
	// after it.
	Prompt string
	Footer string
}

// Frame is a page laid out for one screen size.
type Frame struct {
	Rows                 []Line
	CursorRow, CursorCol int
}

// more ends a body cut to fit; the full text is a command away (status).
const more = "  ... (more below the screen: menu, status)"

// Frame lays the page out on cols x rows. No row reaches the last column,
// so writing the last row can't scroll the screen.
func (p Page) Frame(cols, rows int) Frame {
	if rows < 12 {
		rows = 12
	}
	if cols < 40 {
		cols = 40
	}
	out := make([]Line, rows)
	w := cols - 1
	header := Line{{Text: " "}, {Text: p.Title, Style: Title}}
	if p.Right != "" {
		gap := w - header.Len() - utf8.RuneCountInString(p.Right) - 1
		if gap < 1 {
			gap = 1
		}
		header = append(header, Span{Text: strings.Repeat(" ", gap)}, Span{Text: p.Right, Style: Bold})
	}
	out[0] = header
	rule := Text(" " + strings.Repeat("-", w-1))
	out[1] = rule
	r := 2
	end := rows - 4
	for _, b := range p.Banner {
		if r < end {
			out[r] = indent(b)
			r++
		}
	}
	if len(p.Banner) > 0 && r < end {
		r++
	}
	room := end - r
	body := p.Body
	if len(body) > room {
		body = append(append([]Line(nil), body[:room-1]...), Text(more))
	}
	for _, b := range body {
		out[r] = indent(b)
		r++
	}
	out[rows-4] = rule
	out[rows-3] = Text(" " + p.Keys)
	out[rows-2] = Text(" " + p.Prompt)
	out[rows-1] = Text(" " + p.Footer)
	for i := range out {
		out[i] = out[i].cut(w)
	}
	return Frame{Rows: out, CursorRow: rows - 2, CursorCol: 1 + utf8.RuneCountInString(p.Prompt)}
}

func indent(l Line) Line { return append(Line{{Text: " "}}, l...) }

// Text is the frame as plain text, one row a line, trailing spaces
// trimmed: the golden-screen form.
func (f Frame) Text() string {
	var b strings.Builder
	for _, r := range f.Rows {
		b.WriteString(strings.TrimRight(r.String(), " "))
		b.WriteByte('\n')
	}
	return b.String()
}
