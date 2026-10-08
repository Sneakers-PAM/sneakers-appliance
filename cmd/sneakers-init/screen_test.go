// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The kernel keeps all but its emergencies off the consoles: console
// loglevel 1, default 4, minimum 1, boot default 7.
func TestQuietKernelSetsTheConsoleLoglevel(t *testing.T) {
	p := filepath.Join(t.TempDir(), "printk")
	if err := os.WriteFile(p, []byte("4\t4\t1\t7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := quietKernel(p); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "1 4 1 7\n" {
		t.Fatalf("printk %q", b)
	}
}

// init's own screens, which ask on the console, turn the screens loud on
// their first write, once; with no console they still write.
func TestAskingTurnsTheScreensLoudOnce(t *testing.T) {
	var out bytes.Buffer
	n := 0
	w := &asking{w: &out, loud: func() { n++ }}
	for _, s := range []string{"Secure Boot?\n", "Type 1 or 2\n"} {
		if _, err := w.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if n != 1 || out.String() != "Secure Boot?\nType 1 or 2\n" {
		t.Fatalf("loud %d times, wrote %q", n, out.String())
	}
}
