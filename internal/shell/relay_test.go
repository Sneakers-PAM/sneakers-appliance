// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package shell_test

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootshell"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

type syncWriter struct {
	mu sync.Mutex
	b  strings.Builder
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// The relay sends the ticket and size, then the keys in frames and a new
// size, shows what comes back, and ends with the root shell, leaving the
// next key on the terminal.
func TestTheRelayCarriesTheTerminal(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "rs.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	got := make(chan string, 1)
	ready := make(chan struct{})
	var hs rootshell.Handshake
	var sizes [][2]uint16
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		h, rest, err := rootshell.ReadHandshake(c)
		if err != nil {
			return
		}
		hs = h
		close(ready)
		_, _ = c.Write([]byte("root# "))
		r := rootshell.NewReader(rest, func(rows, cols uint16) { sizes = append(sizes, [2]uint16{rows, cols}) })
		buf := make([]byte, 4)
		_, _ = io.ReadFull(r, buf)
		got <- string(buf)
		_, _ = c.Write([]byte("bye\r\n"))
		_ = c.Close()
	}()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close(); _ = pw.Close() }()
	out := &syncWriter{}
	resize := make(chan struct{}, 1)
	rows, cols := uint16(24), uint16(80)
	size := func() (uint16, uint16) { return rows, cols }
	errc := make(chan error, 1)
	go func() { errc <- shell.Relay(context.Background(), sock, "tkt", "xterm", pr, out, size, resize) }()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay never connected")
	}
	rows, cols = 40, 100
	resize <- struct{}{}
	time.Sleep(100 * time.Millisecond)
	_, _ = pw.Write([]byte("id\r\n"))
	select {
	case s := <-got:
		if s != "id\r\n" {
			t.Fatalf("the root shell got %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no keys reached the root shell")
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the relay didn't end with the root shell")
	}
	if hs.Ticket != "tkt" || hs.Rows != 24 || hs.Cols != 80 || hs.Term != "xterm" {
		t.Fatalf("handshake %+v", hs)
	}
	if len(sizes) != 1 || sizes[0] != [2]uint16{40, 100} {
		t.Fatalf("sizes %v", sizes)
	}
	if !strings.Contains(out.String(), "root# ") || !strings.Contains(out.String(), "bye") {
		t.Fatalf("out %q", out.String())
	}
	_, _ = pw.Write([]byte("x"))
	b := make([]byte, 1)
	_ = pr.SetReadDeadline(time.Now().Add(time.Second))
	if n, _ := pr.Read(b); n != 1 || b[0] != 'x' {
		t.Fatal("the relay took a key after the root shell ended")
	}
}
