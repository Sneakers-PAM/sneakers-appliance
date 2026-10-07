// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package console_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/console"
)

// pty makes a terminal at dir/name (a symlink to a pty's slave) and
// returns its master.
func pty(t *testing.T, dir, name string) *os.File {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no /dev/ptmx:", err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("/dev/pts", strconv.Itoa(n)), filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	return m
}

// A serial console with no UART behind it (a VMware VM without a serial
// port) is in the kernel's active list, opens, and fails every write. It's
// left out; the screen is kept.
func TestOpenLeavesOutAConsoleThatTakesNoWrites(t *testing.T) {
	dev := t.TempDir()
	screen := pty(t, dev, "tty0")
	defer func() { _ = screen.Close() }()
	gone := pty(t, dev, "ttyS0")
	// The slave stays openable; once the master is closed, it's hung up
	// and every write fails with EIO, as a port with no UART does.
	hold, err := os.OpenFile(filepath.Join(dev, "ttyS0"), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Close() }()
	_ = gone.Close()

	got, dropped := console.Open(dev, []string{"tty0", "ttyS0", "ttyAMA0"})
	var names []string
	for _, c := range got {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "tty0" {
		t.Fatalf("Open kept %q, want only tty0", names)
	}
	if dropped["ttyS0"] == nil || dropped["ttyAMA0"] == nil {
		t.Fatalf("dropped = %v, want ttyS0 (no writes) and ttyAMA0 (missing)", dropped)
	}
}
