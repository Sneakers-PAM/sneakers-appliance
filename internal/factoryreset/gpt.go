// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package factoryreset

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"unicode/utf16"

	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/partition/gpt"
)

// GPTDisk is the boot disk (or a disk image) at Path.
type GPTDisk struct {
	Path string
	// Notify tells the kernel the numbered partitions are gone (the box
	// sets it; an image file needs nothing).
	Notify func(numbers []int) error
}

func (g *GPTDisk) table() (*gpt.Table, func(), int64, error) {
	d, err := diskfs.Open(g.Path, diskfs.WithOpenMode(diskfs.ReadOnly))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("factory reset: open %s: %w", g.Path, err)
	}
	t, err := d.GetPartitionTable()
	if err != nil {
		_ = d.Close()
		return nil, nil, 0, fmt.Errorf("factory reset: read the partition table: %w", err)
	}
	gt, ok := t.(*gpt.Table)
	if !ok {
		_ = d.Close()
		return nil, nil, 0, fmt.Errorf("factory reset: %s has a %s partition table, not a GPT", g.Path, t.Type())
	}
	return gt, func() { _ = d.Close() }, d.Size, nil
}

// Partitions lists the partitions in the primary GPT.
func (g *GPTDisk) Partitions() ([]Region, error) {
	t, closeFn, _, err := g.table()
	if err != nil {
		return nil, err
	}
	defer closeFn()
	ss := int64(t.LogicalSectorSize)
	var out []Region
	for _, p := range t.Partitions {
		if p.Type == gpt.Unused {
			continue
		}
		out = append(out, Region{Number: p.Index, Label: p.Name, Start: int64(p.Start) * ss, Size: (int64(p.End) - int64(p.Start) + 1) * ss}) // #nosec G115 -- sector numbers on a real disk fit an int64
	}
	slices.SortFunc(out, func(a, b Region) int { return a.Number - b.Number })
	return out, nil
}

// Delete removes the numbered partitions from both GPT copies, then tells
// the kernel.
func (g *GPTDisk) Delete(numbers []int) error {
	d, err := diskfs.Open(g.Path, diskfs.WithOpenMode(diskfs.ReadWrite))
	if err != nil {
		return fmt.Errorf("factory reset: open %s: %w", g.Path, err)
	}
	defer func() { _ = d.Close() }()
	t, err := d.GetPartitionTable()
	if err != nil {
		return fmt.Errorf("factory reset: read the partition table: %w", err)
	}
	gt, ok := t.(*gpt.Table)
	if !ok {
		return fmt.Errorf("factory reset: %s has no GPT", g.Path)
	}
	gt.Partitions = slices.DeleteFunc(gt.Partitions, func(p *gpt.Partition) bool {
		return p.Type == gpt.Unused || slices.Contains(numbers, p.Index)
	})
	w, err := d.Backend.Writable()
	if err != nil {
		return err
	}
	// Written straight through the table, not Disk.Partition: that asks
	// the kernel to re-read the whole table, which it refuses while the
	// ESP is mounted. Notify drops just these partitions instead.
	if err := gt.Write(w, d.Size); err != nil {
		return fmt.Errorf("factory reset: write the partition table: %w", err)
	}
	if g.Notify != nil {
		return g.Notify(numbers)
	}
	return nil
}

// BackupLabels lists the partition names in the backup GPT at the end of
// the disk, read directly so the check doesn't depend on the primary.
func (g *GPTDisk) BackupLabels() ([]string, error) {
	t, closeFn, size, err := g.table()
	if err != nil {
		return nil, err
	}
	closeFn()
	ss := int64(t.LogicalSectorSize)
	f, err := os.Open(g.Path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	hdr := make([]byte, ss)
	if _, err := f.ReadAt(hdr, size-ss); err != nil {
		return nil, fmt.Errorf("factory reset: read the backup GPT header: %w", err)
	}
	if !bytes.Equal(hdr[:8], []byte("EFI PART")) {
		return nil, fmt.Errorf("factory reset: no backup GPT header at the end of %s", g.Path)
	}
	lba := int64(binary.LittleEndian.Uint64(hdr[72:80]))     // #nosec G115 -- a sector number on the disk
	count := int64(binary.LittleEndian.Uint32(hdr[80:84]))   // entries in the array
	entSize := int64(binary.LittleEndian.Uint32(hdr[84:88])) // bytes per entry
	if count > 1024 || entSize < 128 || entSize > 1024 {
		return nil, fmt.Errorf("factory reset: the backup GPT header is implausible (%d entries of %d bytes)", count, entSize)
	}
	arr := make([]byte, count*entSize)
	if _, err := f.ReadAt(arr, lba*ss); err != nil {
		return nil, fmt.Errorf("factory reset: read the backup GPT entries: %w", err)
	}
	var out []string
	for i := range count {
		e := arr[i*entSize : (i+1)*entSize]
		if bytes.Equal(e[:16], make([]byte, 16)) {
			continue
		}
		u := make([]uint16, 36)
		for j := range u {
			u[j] = binary.LittleEndian.Uint16(e[56+2*j:])
		}
		if n := slices.Index(u, 0); n >= 0 {
			u = u[:n]
		}
		out = append(out, string(utf16.Decode(u)))
	}
	return out, nil
}

// WriteAt writes b at off and syncs it.
func (g *GPTDisk) WriteAt(b []byte, off int64) (int, error) {
	f, err := os.OpenFile(g.Path, os.O_WRONLY, 0)
	if err != nil {
		return 0, err
	}
	n, err := f.WriteAt(b, off)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return n, err
}

// ReadAt reads len(b) bytes at off.
func (g *GPTDisk) ReadAt(b []byte, off int64) (int, error) {
	f, err := os.Open(g.Path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	return f.ReadAt(b, off)
}
