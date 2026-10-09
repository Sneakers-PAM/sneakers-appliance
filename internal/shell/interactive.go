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
	t.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		if key != '\t' {
			return "", 0, false
		}
		done := CompleteFor(e.Origin, e.Product, line[:pos], e.Values...)
		if done == line[:pos] {
			return "", 0, false
		}
		return done + line[pos:], len(done), true
	}
	session := *e
	session.Out, session.Err = t, t
	session.In = &termLines{t: t}
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
	t   *term.Terminal
	buf []byte
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
	words := strings.Fields(typed)
	trailing := strings.HasSuffix(typed, " ") || typed == ""
	if !trailing && len(words) > 0 {
		words = words[:len(words)-1]
	}
	partial := ""
	if !trailing {
		f := strings.Fields(typed)
		partial = f[len(f)-1]
	}
	seen := map[string]bool{}
	var next []string
	for _, name := range append(NamesFor(o, p, values...), "help", "exit") {
		p := strings.Fields(name)
		if len(p) <= len(words) || !hasPrefixWords(p, words) {
			continue
		}
		w := p[len(words)]
		if strings.HasPrefix(w, partial) && !seen[w] {
			seen[w] = true
			next = append(next, w)
		}
	}
	if len(next) == 0 {
		return typed
	}
	common := next[0]
	for _, w := range next[1:] {
		common = commonPrefix(common, w)
	}
	if len(next) == 1 {
		common += " "
	}
	base := strings.Join(words, " ")
	if base != "" {
		base += " "
	}
	return base + common
}

func hasPrefixWords(p, words []string) bool {
	for i, w := range words {
		if p[i] != w {
			return false
		}
	}
	return true
}

func commonPrefix(a, b string) string {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return a[:n]
}
