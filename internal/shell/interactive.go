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
		done, options := Completions(e, head)
		if done != head {
			tabbed = false
			return done + line[pos:], len(done), true
		}
		if tabbed && lastTab == head && len(options) > 1 {
			_, _ = io.WriteString(t, listing(options))
		}
		tabbed, lastTab = true, head
		return "", 0, false
	}
	session := *e
	session.Out, session.Err = t, t
	session.In = &termLines{t: t, prompt: prompt}
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
		_ = Run(ctx, &session, line)
	}
}

// termLines lets a command read a confirmation from the terminal it runs
// on: each Read returns one more line.
type termLines struct {
	t      *term.Terminal
	prompt string
	buf    []byte
}

// AskLine reads one line with prompt as the terminal's prompt, then puts
// the menu's prompt back: a command's question is its own line, and the
// menu's prompt never follows it on the same line.
func (r *termLines) AskLine(prompt string) (string, error) {
	r.buf = nil
	r.t.SetPrompt(prompt)
	defer r.t.SetPrompt(r.prompt)
	return r.t.ReadLine()
}

func (r *termLines) Read(p []byte) (int, error) {
	if len(r.buf) == 0 {
		line, err := r.t.ReadLine()
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

// listing is the candidates a second Tab shows, in columns.
func listing(options []string) string {
	w := 0
	for _, o := range options {
		w = max(w, len(o))
	}
	var b strings.Builder
	for i, o := range options {
		b.WriteString("  " + o)
		if (i+1)%4 == 0 || i == len(options)-1 {
			b.WriteString("\n")
		} else {
			b.WriteString(strings.Repeat(" ", w-len(o)))
		}
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
