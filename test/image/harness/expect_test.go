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
