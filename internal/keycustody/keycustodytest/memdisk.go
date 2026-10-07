// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package keycustodytest is an in-memory boot disk for tests of the code
// around key custody: volumes that keep their header tokens and check the
// key they're unlocked with, and a key-file partition that can be wiped.
package keycustodytest

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"sync"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
)

// Disk is a boot disk that survives "reboots": a fresh keycustody.Custody
// over the same Disk sees what the last one wrote.
type Disk struct {
	mu sync.Mutex
	// SizeBytes is the disk's size; zero is 100 GiB.
	SizeBytes int64
	// Created is the plan the last Create was given.
	Created []disk.Partition
	// Mounted lists the volumes in the order they were unlocked.
	Mounted []string
	state   *Volume
	backup  *Volume
	keyfile *Keyfile
}

// Size reports SizeBytes.
func (d *Disk) Size() int64 {
	if d.SizeBytes == 0 {
		return 100 * disk.GiB
	}
	return d.SizeBytes
}

// Arch is amd64.
func (d *Disk) Arch() string { return "amd64" }

// Create makes empty volumes (and a key file when planned).
func (d *Disk) Create(_ context.Context, plan []disk.Partition) (keycustody.Volume, keycustody.Volume, keycustody.KeyfileStore, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Created = plan
	d.state, d.backup, d.keyfile = &Volume{name: "state", d: d}, &Volume{name: "backup", d: d}, nil
	for _, p := range plan {
		if p.Label == disk.LabelKeyfile {
			d.keyfile = &Keyfile{}
		}
	}
	return d.state, d.backup, d.keyfileStore(), nil
}

// Open returns the volumes Create made.
func (d *Disk) Open(context.Context) (keycustody.Volume, keycustody.Volume, keycustody.KeyfileStore, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.state == nil {
		return nil, nil, nil, errors.New("keycustodytest: no first-boot partitions")
	}
	return d.state, d.backup, d.keyfileStore(), nil
}

// keyfileStore keeps a missing key file a nil interface, as the box's Open
// returns it.
func (d *Disk) keyfileStore() keycustody.KeyfileStore {
	if d.keyfile == nil {
		return nil
	}
	return d.keyfile
}

// WipeKeyfile zeroes the key-file partition.
func (d *Disk) WipeKeyfile() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.keyfile != nil {
		d.keyfile.key = make([]byte, keycustody.KeySize)
	}
}

// Volume is one LUKS2 volume in memory.
type Volume struct {
	name   string
	d      *Disk
	key    []byte
	tokens map[int][]byte
}

// Format records key as the volume's key and clears its tokens.
func (v *Volume) Format(_ context.Context, key []byte) error {
	v.key, v.tokens = bytes.Clone(key), map[int][]byte{}
	return nil
}

// IsLUKS reports whether Format ran.
func (v *Volume) IsLUKS(context.Context) bool { return v.key != nil }

// ImportToken stores a token.
func (v *Volume) ImportToken(_ context.Context, id int, tokenJSON []byte) error {
	if _, used := v.tokens[id]; used {
		return errors.New("keycustodytest: token id in use")
	}
	v.tokens[id] = bytes.Clone(tokenJSON)
	return nil
}

// ExportToken returns a token.
func (v *Volume) ExportToken(_ context.Context, id int) ([]byte, error) {
	t, ok := v.tokens[id]
	if !ok {
		return nil, errors.New("keycustodytest: no such token")
	}
	return bytes.Clone(t), nil
}

// Tokens returns every token.
func (v *Volume) Tokens(context.Context) (map[int][]byte, error) { return maps.Clone(v.tokens), nil }

// RemoveToken deletes a token.
func (v *Volume) RemoveToken(_ context.Context, id int) error {
	delete(v.tokens, id)
	return nil
}

// Unlock checks key and records the mount.
func (v *Volume) Unlock(_ context.Context, key []byte, _ bool) error {
	if !bytes.Equal(key, v.key) {
		return errors.New("keycustodytest: wrong key")
	}
	v.d.mu.Lock()
	v.d.Mounted = append(v.d.Mounted, v.name)
	v.d.mu.Unlock()
	return nil
}

// Keyfile is the key-file partition in memory.
type Keyfile struct{ key []byte }

// Write keeps the key.
func (k *Keyfile) Write(key []byte) error { k.key = bytes.Clone(key); return nil }

// Read returns the key.
func (k *Keyfile) Read() ([]byte, error) {
	if k.key == nil {
		return nil, errors.New("keycustodytest: empty key file")
	}
	return bytes.Clone(k.key), nil
}
