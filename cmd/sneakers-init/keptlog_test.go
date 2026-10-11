// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/console"
)

// holds reports whether this process has a descriptor open on a file
// under dir.
func holds(t *testing.T, dir string) bool {
	t.Helper()
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	for _, fd := range fds {
		if l, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name())); err == nil && strings.HasPrefix(l, dir+"/") {
			return true
		}
	}
	return false
}

// Once the state is mounted, the shared output since the boot began goes
// to the journal on it; before the volumes are closed the journal lets go
// of its file, so nothing holds the state volume at the unmount, and what
// was written up to then is on it.
func TestTheConsoleLogIsKeptAndLetGoBeforeTheVolumesClose(t *testing.T) {
	state := t.TempDir()
	out, outW := io.Pipe()
	m := console.Join(out, io.Discard, nil, t.Logf)
	if _, err := io.WriteString(outW, "sneakers-init: phase=normal\n"); err != nil {
		t.Fatal(err)
	}
	k := keepConsoleLog(m, filepath.Join(state, "log", "console.log"), log.Nop())
	if k == nil {
		t.Fatal("no journal on a mounted state")
	}
	if _, err := io.WriteString(outW, "power: draining\n"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if !holds(t, state) {
		t.Fatal("the journal isn't open on the state volume")
	}
	closed := false
	err := closeLogFirst(context.Background(), k, func(context.Context) error {
		closed = true
		if holds(t, state) {
			t.Error("the journal still holds the state volume when the volumes close")
		}
		return nil
	})
	if err != nil || !closed {
		t.Fatalf("the volumes weren't closed: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(state, "log", "console.log")) // #nosec G304 -- the test's own file
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), " sneakers-init: phase=normal\n") || !strings.Contains(string(b), " power: draining\n") {
		t.Fatalf("the journal has %q", b)
	}
}

// A state that can't take the journal leaves the box booting without
// one; closing the volumes still works.
func TestNoJournalStillClosesTheVolumes(t *testing.T) {
	m := console.Join(strings.NewReader(""), io.Discard, nil, t.Logf)
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	k := keepConsoleLog(m, filepath.Join(file, "log", "console.log"), log.Nop())
	if k != nil {
		t.Fatal("a journal under a file")
	}
	closed := false
	if err := closeLogFirst(context.Background(), k, func(context.Context) error { closed = true; return nil }); err != nil || !closed {
		t.Fatalf("closed %v, %v", closed, err)
	}
}
