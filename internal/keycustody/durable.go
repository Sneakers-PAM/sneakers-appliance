// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody

import (
	"os"
	"path/filepath"
)

// syncFile flushes f to the disk; tests watch the order.
var syncFile = func(f *os.File) error { return f.Sync() }

// writeDurable replaces dir/name with data so that a power cut leaves the
// old item or the new one, never an empty file: the data is synced before
// the rename, and the directory after it.
func writeDurable(dir, name string, data []byte) error {
	tmp := filepath.Join(dir, "."+name+".new")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- a sealed item under the state volume
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := syncFile(f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir) // #nosec G304 -- the sealed items' directory
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return syncFile(d)
}
