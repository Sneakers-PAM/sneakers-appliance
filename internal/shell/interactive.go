// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"context"
	"errors"
	"io"
	"strings"

	"golang.org/x/term"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productinfo"
)

// Interactive runs the line CLI on a terminal until exit, quit or end of
// input: a prompt, line editing and history, and tab completion of the
// command words.
func Interactive(ctx context.Context, e *Env, rw io.ReadWriter, prompt string) error {
	t := term.NewTerminal(rw, prompt)
	// Up and Down recall the menu's command lines only: an answer typed at
	// a command's prompt is kept out.
	recall := &menuRecall{History: t.History}
	t.History = recall
	// Tab completes the word before the cursor; a second Tab that can't
	// complete any further lists the candidates, and the prompt and the
	// line are drawn again under them.
	lastTab := ""
	tabbed := false
	t.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		if key != '\t' {
			tabbed = false
			return "", 0, false
		}
		head := line[:pos]
		done, options := completions(e, head)
		if done != head {
			tabbed = false
			return done + line[pos:], len(done), true
		}
		if tabbed && lastTab == head && len(options) > 1 {
			// The typed line stays above the list, as in a shell; the
			// terminal draws the prompt and the line again under it.
			_, _ = io.WriteString(t, prompt+line+"\n"+listing(options))
		}
		tabbed, lastTab = true, head
		return "", 0, false
	}
	session := *e
	if session.History == nil {
		session.History = &History{}
	}
	session.Out, session.Err = t, t
	session.In = &termLines{t: t, prompt: prompt, recall: recall}
	_, _ = io.WriteString(t, "Type help for the commands, exit to leave.\n")
	for {
		if ctx.Err() != nil {
			return nil
		}
		line, err := t.ReadLine()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch strings.TrimSpace(line) {
		case "":
			continue
		case "exit", "quit", "logout":
			return nil
		}
		session.History.Add(line)
		_ = Run(ctx, &session, line)
	}
}

// menuRecall is the terminal's arrow-key recall, which takes no lines
// while a command reads from the terminal.
type menuRecall struct {
	term.History
	off bool
}

func (h *menuRecall) Add(entry string) {
	if !h.off {
		h.History.Add(entry)
	}
}

// termLines lets a command read a confirmation from the terminal it runs
// on: each Read returns one more line. Nothing it reads enters recall.
type termLines struct {
	t      *term.Terminal
	prompt string
	buf    []byte
	recall *menuRecall
}

// AskLine reads one line with prompt as the terminal's prompt, then puts
// the menu's prompt back: a command's question is its own line, and the
// menu's prompt never follows it on the same line. The answer stays out
// of recall.
func (r *termLines) AskLine(prompt string) (string, error) {
	r.buf = nil
	r.t.SetPrompt(prompt)
	defer r.t.SetPrompt(r.prompt)
	return r.unrecalled(r.t.ReadLine)
}

// AskSecret reads one line with prompt and no echo, for a code or a
// password; like every answer it stays out of recall.
func (r *termLines) AskSecret(prompt string) (string, error) {
	r.buf = nil
	return r.unrecalled(func() (string, error) { return r.t.ReadPassword(prompt) })
}

func (r *termLines) unrecalled(read func() (string, error)) (string, error) {
	r.recall.off = true
	defer func() { r.recall.off = false }()
	return read()
}

func (r *termLines) Read(p []byte) (int, error) {
	if len(r.buf) == 0 {
		line, err := r.unrecalled(r.t.ReadLine)
		if err != nil {
			return 0, err
		}
		r.buf = []byte(line + "\n")
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// Complete extends the typed words to the longest unambiguous base command
// path for origin o.
func Complete(o Origin, typed string) string { return CompleteFor(o, productinfo.Info{}, typed) }

// CompleteFor is Complete with product p's commands too.
func CompleteFor(o Origin, p productinfo.Info, typed string, values ...Value) string {
	line, _ := Completions(&Env{Origin: o, Product: p, Values: values}, typed)
	return line
}

// listColumns is how many candidates without descriptions a list shows
// per line; past manyCandidates (the time zones) they go in columns
// rather than one per line.
const (
	listColumns    = 4
	manyCandidates = 24
)

// listing is the candidates a second Tab shows: one per line with what
// each does, the way a shell lists them, or, for a long list of bare
// words, in columns.
func listing(options []Candidate) string {
	w, notes := 0, false
	for _, o := range options {
		w = max(w, len(o.Word))
		notes = notes || o.Note != ""
	}
	var b strings.Builder
	if !notes && len(options) > manyCandidates {
		for i, o := range options {
			b.WriteString("  " + o.Word)
			if (i+1)%listColumns == 0 || i == len(options)-1 {
				b.WriteString("\n")
			} else {
				b.WriteString(strings.Repeat(" ", w-len(o.Word)))
			}
		}
		return b.String()
	}
	for _, o := range options {
		if o.Note == "" {
			b.WriteString("  " + o.Word + "\n")
			continue
		}
		b.WriteString("  " + o.Word + strings.Repeat(" ", w-len(o.Word)) + "  " + o.Note + "\n")
	}
	return b.String()
}

func commonPrefix(a, b string) string {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return a[:n]
}
