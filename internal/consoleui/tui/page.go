// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"
	"unicode/utf8"
)

// Width is the widest the body block gets: what fits inside the frame on
// the 64 columns the large font gives a 1024x768 screen. Pages wrap their
// text to it.
const Width = 56

// Page is one full-screen state: the header (the mark and the wordmark on
// the boot and info screens, one row elsewhere), the body, the line being
// typed, and the keys that work here.
type Page struct {
	// Big puts the mark and the wordmark above the body.
	Big bool
	// Name and Version are the wordmark (on the big pages the version is
	// on its own line under the name); Info is the one-row header's right
	// side (the slot and the node count, say).
	Name, Version, Info string
	Body                []Line
	// Prompt is the text before the typing position; the cursor waits
	// after it. With no prompt the cursor waits after the keys, and a page
	// with neither hides it.
	Prompt string
	Keys   Line
}

// Frame is a page laid out for one screen size.
type Frame struct {
	Rows                 []Line
	Cursor               bool
	CursorRow, CursorCol int
}

// mark is the sneaker with the keyhole, drawn from the brand mark: the
// collar at the heel, the laces on the vamp, and the sole underneath.
var mark = []Line{
	{{Text: "    .------.", Style: Brand}},
	{{Text: "   /  ", Style: Brand}, {Text: ".-.", Style: Keyhole}, {Text: "   \\ = = =", Style: Brand}},
	{{Text: "  |  ", Style: Brand}, {Text: "( o )", Style: Keyhole}, {Text: "   '------._", Style: Brand}},
	{{Text: "  |   ", Style: Brand}, {Text: "|_|", Style: Keyhole}, {Text: "            '\\", Style: Brand}},
	{{Text: " (=====================)", Style: Accent}},
}

// small is the mark in the one-row header.
var small = Line{{Text: "/", Style: Brand}, {Text: "o", Style: Keyhole}, {Text: "\\__", Style: Brand}}

// MarkLines is the mark as plain text, a line a row.
func MarkLines() []string {
	out := make([]string, len(mark))
	for i, l := range mark {
		out[i] = l.String()
	}
	return out
}

// BlockWidth is the body block's width on a cols-wide terminal.
func BlockWidth(cols int) int {
	inner := frameWidth(cols) - 2
	if w := inner - 4; w < Width {
		return w
	}
	return Width
}

func frameWidth(cols int) int {
	if cols < 40 {
		cols = 40
	}
	return cols
}

// Frame lays the page out on cols x rows: a border round the whole
// screen, and the block centred inside it.
func (p Page) Frame(cols, rows int) Frame {
	if rows < 12 {
		rows = 12
	}
	fw := frameWidth(cols)
	inner := fw - 2
	bw := BlockWidth(cols)
	lp := (inner - bw) / 2
	pad := Line{{Text: strings.Repeat(" ", lp)}}

	interior := make([]Line, rows-2)
	top, bottom := 0, len(interior)
	// The header's and the keys' rules span the frame, corners and all.
	rules := map[int]bool{}
	edge := Line{{Text: strings.Repeat(" ", max(lp-1, 1))}}
	promptRow, promptCol := -1, 0
	if len(p.Keys) > 0 {
		bottom--
		keys := cat(edge, p.Keys)
		if p.Prompt == "" {
			// A key is typed and Enter pressed, so the cursor waits after
			// the keys.
			keys = append(keys, Span{Text: "   "})
			promptRow, promptCol = bottom, 1+keys.Len()
		}
		interior[bottom] = keys
		bottom--
		rules[bottom] = true
	}
	if p.Prompt != "" {
		bottom--
		promptRow, promptCol = bottom, 1+lp+utf8.RuneCountInString(p.Prompt)
		interior[bottom] = cat(pad, Text(p.Prompt))
	}
	var content []Line
	if p.Big {
		mw := 0
		for _, l := range mark {
			if n := l.Len(); n > mw {
				mw = n
			}
		}
		mp := Line{{Text: strings.Repeat(" ", (inner-mw)/2)}}
		for _, l := range mark {
			content = append(content, cat(mp, l))
		}
		content = append(content, nil, centre(Line{{Text: p.Name, Style: Strong}}, inner))
		if p.Version != "" {
			content = append(content, centre(Line{{Text: p.Version, Style: Dim}}, inner))
		}
		content = append(content, nil)
	} else {
		head := cat(edge, small, Line{{Text: "  ", Style: Strong}}, Line{{Text: p.Name, Style: Strong}})
		if v := strings.TrimSpace(p.Version + "  " + p.Info); v != "" {
			head = append(head, Span{Text: "   " + v, Style: Dim})
		}
		interior[0] = head
		rules[1] = true
		top = 2
		content = append(content, nil)
	}
	for _, b := range p.Body {
		content = append(content, cat(pad, b))
	}
	room := bottom - top
	if !p.Big && len(content) > room {
		// Short of room, the body moves up to the header's rule.
		content = content[1:]
	}
	if !p.Big {
		// Still short, the body's blank rows go, from the top, before
		// anything is cut.
		for i := 0; i < len(content) && len(content) > room; {
			if blank(content[i]) {
				content = append(content[:i:i], content[i+1:]...)
				continue
			}
			i++
		}
	}
	if p.Big || len(content) < room {
		// A blank row before the keys, so the body never runs into them.
		room--
	}
	if len(content) > room {
		content = append(content[:room-1:room-1], cat(pad, Styled(Dim, "...")))
	}
	at := top
	if p.Big {
		at += (room - len(content)) / 2
	}
	for _, l := range content {
		interior[at] = l
		at++
	}

	out := make([]Line, rows)
	border := Line{{Text: "+" + strings.Repeat("-", inner) + "+", Style: Brand}}
	out[0], out[rows-1] = border, border
	bar := Span{Text: "|", Style: Brand}
	for i, l := range interior {
		if rules[i] {
			out[i+1] = border
			continue
		}
		l = l.cut(inner)
		if n := inner - l.Len(); n > 0 {
			l = append(l, Span{Text: strings.Repeat(" ", n)})
		}
		out[i+1] = append(append(Line{bar}, l...), bar)
	}
	f := Frame{Rows: out}
	if promptRow >= 0 {
		f.Cursor, f.CursorRow, f.CursorCol = true, promptRow+1, promptCol
	}
	return f
}

func centre(l Line, width int) Line {
	n := (width - l.Len()) / 2
	if n <= 0 {
		return l
	}
	return cat(Line{{Text: strings.Repeat(" ", n)}}, l)
}

func cat(ls ...Line) Line {
	var out Line
	for _, l := range ls {
		out = append(out, l...)
	}
	return out
}

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

// Coloured is the frame as the screen gets it in colour, with each escape
// written as \e: the coloured golden-screen form.
func (f Frame) Coloured() string {
	var b strings.Builder
	for _, r := range f.Rows {
		b.WriteString(strings.ReplaceAll(r.encode(true), "\x1b", `\e`))
		b.WriteByte('\n')
	}
	return b.String()
}

// blank reports whether l shows nothing but spaces.
func blank(l Line) bool {
	for _, sp := range l {
		if strings.TrimSpace(sp.Text) != "" {
			return false
		}
	}
	return true
}
