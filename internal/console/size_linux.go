// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package console

import (
	"fmt"
	"io"
	"path/filepath"
	"unsafe"

	log "github.com/Bugs5382/go-log"
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

// The kernel's built-in fonts, largest first. The UKI's command line
// selects LargeFont; the others are the fallbacks when it leaves too few
// columns or rows. The names are the kernel's (font_desc.name).
const (
	LargeFont  = "TER16x32"
	MediumFont = "SUN12x22"
	SmallFont  = "VGA8x16"
)

// NeedsSmallFont reports whether a screen of cols x rows under its
// current font is too small for the console's screens, so it needs a
// smaller font.
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

// PickFont leaves a screen that already fits alone and returns "".
// Otherwise it sets each font in turn, largest first, and returns the
// first that gives the console's screens the room they need, or the
// smallest when none does.
func PickFont(size func() (cols, rows int), set func(name string) error) (string, error) {
	if !NeedsSmallFont(size()) {
		return "", nil
	}
	for _, font := range []string{LargeFont, MediumFont, SmallFont} {
		if err := set(font); err != nil {
			return "", err
		}
		if !NeedsSmallFont(size()) {
			return font, nil
		}
	}
	return SmallFont, nil
}

// FitFont picks the screen's (tty0's) font with PickFont: a framebuffer
// below 1024x768 is too small for the large font. It returns the font it
// set, or "" when it left the screen alone.
func FitFont(devDir string) (string, error) {
	tty := filepath.Join(devDir, "tty0")
	return PickFont(func() (int, int) { return winsize(tty) }, func(font string) error {
		fd, err := unix.Open(tty, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(fd) }()
		name := append([]byte(font), 0)
		op := consoleFontOp{op: kdFontOpSetDeflt, data: &name[0]}
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), kdFontOp, uintptr(unsafe.Pointer(&op))); errno != 0 { // #nosec G103 -- the kernel's KDFONTOP takes a pointer to its struct
			return fmt.Errorf("%s: %w", font, errno)
		}
		return nil
	})
}

// FitAndLogFont runs FitFont and writes the outcome to w, with the
// screen's size. It has its own logger because the console services log
// at error level, and this line is how to tell which font a box's screen
// ended up with.
func FitAndLogFont(devDir string, w io.Writer, service string) {
	lg := log.NewLoggerWithOptions(service, log.WithOutput(w), log.WithDefaultFormat(log.FormatJSON), log.WithDefaultLevel(log.LevelInfo))
	font, err := FitFont(devDir)
	cols, rows := winsize(filepath.Join(devDir, "tty0"))
	size := []log.Field{log.F("cols", cols), log.F("rows", rows)}
	switch {
	case err != nil:
		lg.Error(err, "console: the font couldn't be set", size...)
	case font == "":
		lg.Info("console: the screen fits its font; left alone", size...)
	default:
		lg.Info("console: font picked for the screen", append(size, log.F("font", font))...)
	}
}
