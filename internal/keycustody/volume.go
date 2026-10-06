// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody

import (
	"context"
	"fmt"
	"os"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/luks"
)

// Mounter makes and mounts the filesystem of an opened volume.
type Mounter interface {
	Mkfs(ctx context.Context, device string) error
	Mount(ctx context.Context, device, target string) error
}

// LUKSVolume is a real LUKS2 partition, opened as /dev/mapper/<Name> and
// mounted at Target.
type LUKSVolume struct {
	*luks.Device
	Name    string
	Target  string
	Mounter Mounter
}

// Unlock opens the volume, makes its filesystem the first time, and mounts
// it.
func (v *LUKSVolume) Unlock(ctx context.Context, key []byte, mkfs bool) error {
	vol, err := v.Open(ctx, key, v.Name)
	if err != nil {
		return err
	}
	if mkfs {
		if err := v.Mounter.Mkfs(ctx, vol.Path); err != nil {
			return fmt.Errorf("keycustody: mkfs %s: %w", vol.Path, err)
		}
	}
	if err := os.MkdirAll(v.Target, 0o700); err != nil {
		return err
	}
	return v.Mounter.Mount(ctx, vol.Path, v.Target)
}

// FileKeyfile is the key-file partition as a block device: the key sits in
// its first bytes.
type FileKeyfile struct{ Path string }

// Write writes and syncs the key.
func (f FileKeyfile) Write(key []byte) error {
	fh, err := os.OpenFile(f.Path, os.O_WRONLY, 0) // #nosec G304 -- the key-file partition's device node
	if err != nil {
		return err
	}
	if _, err := fh.WriteAt(key, 0); err != nil {
		_ = fh.Close()
		return err
	}
	if err := fh.Sync(); err != nil {
		_ = fh.Close()
		return err
	}
	return fh.Close()
}

// Read reads the key.
func (f FileKeyfile) Read() ([]byte, error) {
	fh, err := os.Open(f.Path) // #nosec G304 -- as above
	if err != nil {
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	key := make([]byte, KeySize)
	if _, err := fh.ReadAt(key, 0); err != nil {
		return nil, err
	}
	return key, nil
}
