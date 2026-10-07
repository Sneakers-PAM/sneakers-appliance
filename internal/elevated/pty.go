// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package elevated

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// openPTY opens a new pseudo-terminal pair from /dev/ptmx.
func openPTY() (master, slave *os.File, err error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("pty: %w", err)
	}
	master = os.NewFile(uintptr(fd), "/dev/ptmx") // #nosec G115 -- a file descriptor
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		_ = master.Close()
		return nil, nil, fmt.Errorf("pty: unlock: %w", err)
	}
	n, err := unix.IoctlGetUint32(fd, unix.TIOCGPTN)
	if err != nil {
		_ = master.Close()
		return nil, nil, fmt.Errorf("pty: number: %w", err)
	}
	name := fmt.Sprintf("/dev/pts/%d", n)
	sfd, err := unix.Open(name, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = master.Close()
		return nil, nil, fmt.Errorf("pty: %w", err)
	}
	return master, os.NewFile(uintptr(sfd), name), nil // #nosec G115 -- a file descriptor
}

// CopySize sets pty's window size to from's.
func CopySize(from, pty *os.File) error {
	ws, err := unix.IoctlGetWinsize(int(from.Fd()), unix.TIOCGWINSZ) // #nosec G115 -- a file descriptor
	if err != nil {
		return err
	}
	return unix.IoctlSetWinsize(int(pty.Fd()), unix.TIOCSWINSZ, ws) // #nosec G115 -- a file descriptor
}
