// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The serial log grows a few bytes at a time as the UART sends them, so a
// read can end mid-line. ExpectLine matches only lines the console has
// finished, and so returns the whole line, not the part that was in.
func TestExpectLineWaitsForTheWholeLine(t *testing.T) {
	serial := filepath.Join(t.TempDir(), "serial.log")
	partial := "boot\r\nlab-hook: after the reinstall: product data: 2026-10-31T21:0"
	if err := os.WriteFile(serial, []byte(partial), 0o600); err != nil {
		t.Fatal(err)
	}
	vm := &VM{t: t, serial: serial, done: make(chan struct{})}
	if got := vm.Expect(`lab-hook: after the reinstall: .*`, time.Second); !strings.HasSuffix(got, "21:0") {
		t.Fatalf("Expect on the part that was in: %q", got)
	}
	go func() {
		time.Sleep(700 * time.Millisecond)
		f, err := os.OpenFile(serial, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- the test's own file
		if err != nil {
			return
		}
		_, _ = f.WriteString("7:13Z phased pods ready: True True\r\nmore")
		_ = f.Close()
	}()
	got := vm.ExpectLine(`lab-hook: after the reinstall: .*`, 10*time.Second)
	if strings.TrimRight(got, "\r") != "lab-hook: after the reinstall: product data: 2026-10-31T21:07:13Z phased pods ready: True True" {
		t.Fatalf("ExpectLine = %q", got)
	}
}

// The telemetry leg's hook says the pods at the end of every restart, so
// after a retry the console holds the failed restart's line too.
// ExpectLineAfter skips it and waits for the line the retry says.
func TestExpectLineAfterSkipsTheLineBeforeTheMark(t *testing.T) {
	serial := filepath.Join(t.TempDir(), "serial.log")
	if err := os.WriteFile(serial, []byte("lab-hook: realci: pods telemetry version=1: failed\r\nlab-hook: realci: tel"), 0o600); err != nil {
		t.Fatal(err)
	}
	vm := &VM{t: t, serial: serial, done: make(chan struct{})}
	mark := vm.Mark()
	go func() {
		time.Sleep(700 * time.Millisecond)
		f, err := os.OpenFile(serial, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- the test's own file
		if err != nil {
			return
		}
		_, _ = f.WriteString("emetry restart=done\r\nlab-hook: realci: pods telemetry version=1: retried\r\n")
		_ = f.Close()
	}()
	got := vm.ExpectLineAfter(mark, `realci: pods telemetry version=.*`, 10*time.Second)
	if strings.TrimRight(got, "\r") != "realci: pods telemetry version=1: retried" {
		t.Fatalf("ExpectLineAfter = %q", got)
	}
}
