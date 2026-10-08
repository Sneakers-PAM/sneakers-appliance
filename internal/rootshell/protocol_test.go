// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package rootshell_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootshell"
)

func TestTheHandshakeRoundTrips(t *testing.T) {
	var b bytes.Buffer
	in := rootshell.Handshake{Ticket: "tkt", Term: "xterm-256color", Rows: 40, Cols: 120}
	if err := rootshell.WriteHandshake(&b, in); err != nil {
		t.Fatal(err)
	}
	b.WriteString("rest")
	got, rest, err := rootshell.ReadHandshake(&b)
	if err != nil || got != in {
		t.Fatalf("got %+v %v", got, err)
	}
	if tail, _ := io.ReadAll(rest); string(tail) != "rest" {
		t.Fatalf("the bytes after the handshake: %q", tail)
	}
}

func TestAnOversizedHandshakeIsRefused(t *testing.T) {
	if _, _, err := rootshell.ReadHandshake(strings.NewReader(strings.Repeat("x", 10000))); err == nil {
		t.Fatal("no limit on the handshake")
	}
	if _, _, err := rootshell.ReadHandshake(strings.NewReader("{}\n")); err == nil {
		t.Fatal("a handshake without a ticket")
	}
}

func TestFramesCarryDataAndSizes(t *testing.T) {
	var b bytes.Buffer
	_ = rootshell.WriteData(&b, []byte("ls -l\r"))
	_ = rootshell.WriteResize(&b, 50, 160)
	_ = rootshell.WriteData(&b, []byte("exit\r"))
	var sizes [][2]uint16
	r := rootshell.NewReader(&b, func(rows, cols uint16) { sizes = append(sizes, [2]uint16{rows, cols}) })
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ls -l\rexit\r" {
		t.Fatalf("data %q", data)
	}
	if len(sizes) != 1 || sizes[0] != [2]uint16{50, 160} {
		t.Fatalf("sizes %v", sizes)
	}
}

func TestAnUnknownFrameEndsTheStream(t *testing.T) {
	r := rootshell.NewReader(bytes.NewReader([]byte{9, 0, 1, 'x'}), nil)
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("an unknown frame type was taken")
	}
}
