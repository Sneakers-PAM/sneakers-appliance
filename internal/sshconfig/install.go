// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sshconfig

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Install renders in into a staging directory beside the live one, has
// check (the pinned sshd -t) accept it, and swaps it in whole. A render
// that fails the check is never swapped in: the live files stay as they
// were. It reports whether sshd_config changed. accessd and sneakers-sshd-run
// both install, so the swap holds an flock on <dir>.lock. A nil check is
// for tests without an sshd.
func Install(in Input, check func(dir string) error) (bool, error) {
	if in.Paths.ConfigDir == "" {
		in.Paths = DefaultPaths()
	}
	dir := in.Paths.ConfigDir
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil { // #nosec G301 -- /run/sneakers
		return false, fmt.Errorf("sshconfig: %w", err)
	}
	lock, err := os.OpenFile(dir+".lock", os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- beside the config directory
	if err != nil {
		return false, fmt.Errorf("sshconfig: %w", err)
	}
	defer func() { _ = lock.Close() }()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil { // #nosec G115 -- a descriptor fits an int
		return false, fmt.Errorf("sshconfig: lock: %w", err)
	}
	defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }() // #nosec G115 -- as above

	next, old := dir+".next", dir+".old"
	for _, d := range []string{next, old} {
		if err := os.RemoveAll(d); err != nil {
			return false, fmt.Errorf("sshconfig: %w", err)
		}
	}
	if err := os.MkdirAll(next, 0o755); err != nil { // #nosec G301 -- sshd reads the key files as the logging-in user
		return false, fmt.Errorf("sshconfig: %w", err)
	}
	if err := Render(in, next); err != nil {
		_ = os.RemoveAll(next)
		return false, err
	}
	if check != nil {
		if err := check(next); err != nil {
			_ = os.RemoveAll(next)
			return false, err
		}
	}
	cfg, err := os.ReadFile(filepath.Join(next, "sshd_config")) // #nosec G304 -- the file just rendered
	if err != nil {
		return false, fmt.Errorf("sshconfig: %w", err)
	}
	prev, perr := os.ReadFile(filepath.Join(dir, "sshd_config")) // #nosec G304 -- the live file
	if _, err := os.Stat(dir); err == nil {
		if err := os.Rename(dir, old); err != nil {
			return false, fmt.Errorf("sshconfig: %w", err)
		}
	}
	if err := os.Rename(next, dir); err != nil {
		return false, fmt.Errorf("sshconfig: %w", err)
	}
	if err := os.RemoveAll(old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return true, fmt.Errorf("sshconfig: the previous files weren't removed: %w", err)
	}
	return perr != nil || !bytes.Equal(cfg, prev), nil
}
