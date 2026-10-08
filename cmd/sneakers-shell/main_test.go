// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

// With no terminal, a client in raw mode sends Enter as a bare CR: the
// code has to end there, or the login hangs.
func TestCodeLineEndsOnCROrLF(t *testing.T) {
	for _, in := range []string{"123456\r", "123456\n", "123456\r\n", " 123456 \r"} {
		pr, pw := io.Pipe()
		go func() { _, _ = pw.Write([]byte(in)) }() // the writer stays open, like a live connection
		got := make(chan string, 1)
		go func() {
			line, err := newStdinLines(pr).line()
			if err != nil {
				t.Errorf("%q: %v", in, err)
			}
			got <- line
		}()
		select {
		case line := <-got:
			if line != "123456" {
				t.Errorf("%q: code %q, want 123456", in, line)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%q: the code line never ended", in)
		}
		_ = pw.Close()
	}
}

// The command after the code reads the rest of standard input: nothing of
// it is lost, and the LF of a CRLF isn't an empty first line.
func TestCodeLineLeavesTheRestForTheCommand(t *testing.T) {
	for in, want := range map[string]string{
		"123456\r\nreboot\n": "reboot\n",
		"123456\rreboot\n":   "reboot\n",
		"123456\nreboot\n":   "reboot\n",
		"123456\n\nreboot\n": "\nreboot\n",
		"123456\r\n":         "",
	} {
		r := newStdinLines(iotest.OneByteReader(strings.NewReader(in)))
		if code, err := r.line(); err != nil || code != "123456" {
			t.Fatalf("%q: code %q, %v", in, code, err)
		}
		rest, err := io.ReadAll(r)
		if err != nil || string(rest) != want {
			t.Errorf("%q: rest %q, %v; want %q", in, rest, err, want)
		}
	}
}

func TestCodeLineAtEndOfInput(t *testing.T) {
	if code, err := newStdinLines(strings.NewReader("123456")).line(); err != nil || code != "123456" {
		t.Errorf("code %q, %v", code, err)
	}
	if _, err := newStdinLines(strings.NewReader("")).line(); err == nil {
		t.Error("no input gave a code")
	}
}
