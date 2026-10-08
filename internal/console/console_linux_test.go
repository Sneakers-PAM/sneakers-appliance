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

func setSize(t *testing.T, m *os.File, cols, rows int) {
	t.Helper()
	if err := unix.IoctlSetWinsize(int(m.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(cols), Row: uint16(rows)}); err != nil { // #nosec G115 -- test sizes
		t.Fatal(err)
	}
}

// The screens are laid out for the smallest console that reports a size;
// a serial line reports none and doesn't count.
func TestSizeIsTheSmallestConsoleWithASize(t *testing.T) {
	dev := t.TempDir()
	screen := pty(t, dev, "tty0")
	defer func() { _ = screen.Close() }()
	serial := pty(t, dev, "ttyS0")
	defer func() { _ = serial.Close() }()
	setSize(t, screen, 64, 24)
	if c, r := console.Size(dev, []string{"tty0", "ttyS0"}); c != 64 || r != 24 {
		t.Fatalf("size %dx%d, want 64x24", c, r)
	}
	setSize(t, serial, 80, 20)
	if c, r := console.Size(dev, []string{"tty0", "ttyS0"}); c != 64 || r != 20 {
		t.Fatalf("size %dx%d, want 64x20", c, r)
	}
	if c, r := console.Size(dev, []string{"ttyAMA0"}); c != 80 || r != 24 {
		t.Fatalf("no console with a size: %dx%d, want 80x24", c, r)
	}
}

// The small font is the fallback only when the large one leaves less than
// 64x24; a console with no size never switches.
func TestNeedsSmallFont(t *testing.T) {
	for _, c := range []struct {
		cols, rows int
		want       bool
	}{{64, 24, false}, {80, 25, false}, {40, 15, true}, {64, 23, true}, {0, 0, false}} {
		if got := console.NeedsSmallFont(c.cols, c.rows); got != c.want {
			t.Errorf("%dx%d: %v", c.cols, c.rows, got)
		}
	}
}

// A screen big enough for the large font is left alone.
func TestFitFontLeavesABigScreen(t *testing.T) {
	dev := t.TempDir()
	screen := pty(t, dev, "tty0")
	defer func() { _ = screen.Close() }()
	setSize(t, screen, 64, 24)
	if switched, err := console.FitFont(dev); err != nil || switched {
		t.Fatalf("switched %v: %v", switched, err)
	}
}
