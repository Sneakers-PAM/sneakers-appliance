// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package shell is the closed shell: the appliance commands of spec 2
// Section 2.8 as a line CLI. Words are split here, with no expansion of any
// kind, and every command is a call to an appliance service; nothing in the
// command tree runs a program, so no line can reach /bin/sh.
package shell

import (
	"strings"
	"unicode/utf8"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// MaxLine is the longest command line the shell takes.
const MaxLine = 64 * 1024

// Split breaks line into words. Spaces and tabs separate words; single
// quotes keep everything up to the next single quote; double quotes keep
// everything up to the next unescaped double quote, with \" and \\ as the
// only escapes; outside quotes a backslash keeps the next character. $, `,
// ;, |, &, <, >, *, ? and the rest are ordinary characters. A line over
// MaxLine, with an unbalanced quote, a trailing backslash, invalid UTF-8 or
// a control character (a newline or NUL among them: one command per line)
// is refused with SHELL_PARSE.
func Split(line string) ([]string, error) {
	if len(line) > MaxLine {
		return nil, codes.New(codes.ShellParse, "the command line is longer than %d bytes", MaxLine)
	}
	if !utf8.ValidString(line) {
		return nil, codes.New(codes.ShellParse, "the command line isn't valid UTF-8")
	}
	for _, r := range line {
		if r != '\t' && (r < 0x20 || r == 0x7f) {
			return nil, codes.New(codes.ShellParse, "the command line holds a control character; give one command per line")
		}
	}
	var (
		words []string
		cur   strings.Builder
		in    bool // inside a word
	)
	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch r {
		case ' ', '\t':
			if in {
				words = append(words, cur.String())
				cur.Reset()
				in = false
			}
		case '\'':
			in = true
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				cur.WriteRune(rs[j])
				j++
			}
			if j == len(rs) {
				return nil, codes.New(codes.ShellParse, "a single quote isn't closed")
			}
			i = j
		case '"':
			in = true
			j := i + 1
			for ; j < len(rs) && rs[j] != '"'; j++ {
				if rs[j] == '\\' && j+1 < len(rs) && (rs[j+1] == '"' || rs[j+1] == '\\') {
					j++
				}
				cur.WriteRune(rs[j])
			}
			if j == len(rs) {
				return nil, codes.New(codes.ShellParse, "a double quote isn't closed")
			}
			i = j
		case '\\':
			if i+1 == len(rs) {
				return nil, codes.New(codes.ShellParse, "the line ends with a backslash")
			}
			in = true
			i++
			cur.WriteRune(rs[i])
		default:
			in = true
			cur.WriteRune(r)
		}
	}
	if in {
		words = append(words, cur.String())
	}
	return words, nil
}
