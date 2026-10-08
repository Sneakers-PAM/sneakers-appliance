// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package console

import (
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The size the console's screens need: 64x24, what the large font gives a
// 1024x768 screen.
const (
	MinCols = 64
	MinRows = 24
)

// The default size, for consoles that report none (a serial line).
const (
	defaultCols = 80
	defaultRows = 24
)

// SmallFont is the kernel's built-in 8x16 font, the fallback when the
// large one leaves too few columns or rows.
const SmallFont = "VGA8x16"

// NeedsSmallFont reports whether a screen of cols x rows under the large
// font is too small for the console's screens.
func NeedsSmallFont(cols, rows int) bool {
	return cols > 0 && rows > 0 && (cols < MinCols || rows < MinRows)
}

// winsize is a terminal's size, or 0x0 when it reports none.
func winsize(path string) (cols, rows int) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, 0
	}
	defer func() { _ = unix.Close(fd) }()
	ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	if err != nil {
		return 0, 0
	}
	return int(ws.Col), int(ws.Row)
}

// Size is the size the screens are laid out for: the smallest of the
// active consoles that report a size (the screen does, a serial line
// doesn't), or 80x24 when none does. The same output goes to every
// console, so it has to fit the smallest.
func Size(devDir string, names []string) (cols, rows int) {
	for _, n := range names {
		c, r := winsize(filepath.Join(devDir, filepath.Base(n)))
		if c == 0 || r == 0 {
			continue
		}
		if cols == 0 || c < cols {
			cols = c
		}
		if rows == 0 || r < rows {
			rows = r
		}
	}
	if cols == 0 || rows == 0 {
		return defaultCols, defaultRows
	}
	return cols, rows
}

// consoleFontOp is the kernel's struct console_font_op (KDFONTOP).
type consoleFontOp struct {
	op, flags, width, height, charcount uint32
	data                                *byte
}

const (
	kdFontOp         = 0x4B72
	kdFontOpSetDeflt = 2
)

// FitFont switches the screen (tty0) to the small font when the large one
// leaves it smaller than the console's screens need: a framebuffer below
// 1024x768. It reports whether it switched.
func FitFont(devDir string) (bool, error) {
	tty := filepath.Join(devDir, "tty0")
	if !NeedsSmallFont(winsize(tty)) {
		return false, nil
	}
	fd, err := unix.Open(tty, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(fd) }()
	name := append([]byte(SmallFont), 0)
	op := consoleFontOp{op: kdFontOpSetDeflt, data: &name[0]}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), kdFontOp, uintptr(unsafe.Pointer(&op))); errno != 0 { // #nosec G103 -- the kernel's KDFONTOP takes a pointer to its struct
		return false, errno
	}
	return true, nil
}
