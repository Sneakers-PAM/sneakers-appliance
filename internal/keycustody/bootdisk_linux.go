// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package keycustody

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"time"
	"unicode"
	"unsafe"

	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/partition/gpt"
	"golang.org/x/sys/unix"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/luks"
)

// Where the box mounts the volumes, and the mapped names they open as. The
// state holds all of /var/lib (the box's own state, k0s's data); the power
// controller unmounts everything under /var/lib before a reboot.
const (
	StateTarget  = "/var/lib"
	BackupTarget = "/var/lib/sneakers/backup"
	stateMapped  = "sneakers-state"
	backupMapped = "sneakers-backup"
)

// firstBootLabels are the partitions first boot makes.
var firstBootLabels = []string{disk.LabelKeyfile, disk.LabelState, disk.LabelBackup}

// BootDisk is the box's boot disk at Path (the disk with the ESP): first
// boot adds its partitions to the GPT after the installed ones and tells
// the kernel about each with BLKPG, which works while the ESP and the root
// slot on the same disk are in use. Path may be a disk image, for tests:
// then the kernel isn't told.
type BootDisk struct {
	Path string
	// Cryptsetup runs cryptsetup for the volumes.
	Cryptsetup luks.Runner
	Mounter    Mounter
	// PBKDFArgs are the keyslot's cost on Format.
	PBKDFArgs []string
}

// Size is the disk's size in bytes, 0 when it can't be read (first boot
// then refuses the disk as too small).
func (b *BootDisk) Size() int64 {
	d, err := diskfs.Open(b.Path, diskfs.WithOpenMode(diskfs.ReadOnly))
	if err != nil {
		return 0
	}
	defer func() { _ = d.Close() }()
	return d.Size
}

// Arch is the architecture init runs on.
func (b *BootDisk) Arch() string { return runtime.GOARCH }

// Create replaces any first-boot partitions an earlier, interrupted first
// boot left (they hold no data until the header is written) with plan's,
// and returns the volumes.
func (b *BootDisk) Create(_ context.Context, plan []disk.Partition) (Volume, Volume, KeyfileStore, error) {
	d, err := diskfs.Open(b.Path, diskfs.WithOpenMode(diskfs.ReadWrite))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("keycustody: open %s: %w", b.Path, err)
	}
	t, err := d.GetPartitionTable()
	if err != nil {
		_ = d.Close()
		return nil, nil, nil, fmt.Errorf("keycustody: read the partition table: %w", err)
	}
	gt, ok := t.(*gpt.Table)
	if !ok {
		_ = d.Close()
		return nil, nil, nil, fmt.Errorf("keycustody: %s has no GPT", b.Path)
	}
	var stale []int
	gt.Partitions = slices.DeleteFunc(gt.Partitions, func(p *gpt.Partition) bool {
		if p.Type == gpt.Unused {
			return true
		}
		if slices.Contains(firstBootLabels, p.Name) {
			stale = append(stale, p.Index)
			return true
		}
		return false
	})
	ss := int64(gt.LogicalSectorSize)
	for _, q := range plan {
		gt.Partitions = append(gt.Partitions, &gpt.Partition{
			Index: q.Number, Start: uint64(q.Start / ss), End: uint64((q.Start+q.Size)/ss - 1), // #nosec G115 -- a planned layout on this disk
			Size: uint64(q.Size), Type: gpt.Type(q.Type), Name: q.Label, // #nosec G115 -- as above
		})
	}
	w, err := d.Backend.Writable()
	if err != nil {
		_ = d.Close()
		return nil, nil, nil, err
	}
	// Written through the table, not Disk.Partition: that asks the kernel
	// to re-read the whole table, which it refuses while the ESP is mounted.
	if err := gt.Write(w, d.Size); err != nil {
		_ = d.Close()
		return nil, nil, nil, fmt.Errorf("keycustody: write the partition table: %w", err)
	}
	if err := d.Close(); err != nil {
		return nil, nil, nil, err
	}
	if err := b.tellKernel(stale, plan); err != nil {
		return nil, nil, nil, err
	}
	numbers := map[string]int{}
	for _, q := range plan {
		numbers[q.Label] = q.Number
	}
	return b.volumes(numbers)
}

// Open returns the volumes first boot made.
func (b *BootDisk) Open(context.Context) (Volume, Volume, KeyfileStore, error) {
	d, err := diskfs.Open(b.Path, diskfs.WithOpenMode(diskfs.ReadOnly))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("keycustody: open %s: %w", b.Path, err)
	}
	defer func() { _ = d.Close() }()
	t, err := d.GetPartitionTable()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("keycustody: read the partition table: %w", err)
	}
	gt, ok := t.(*gpt.Table)
	if !ok {
		return nil, nil, nil, fmt.Errorf("keycustody: %s has no GPT", b.Path)
	}
	numbers := map[string]int{}
	for _, p := range gt.Partitions {
		if p.Type != gpt.Unused && slices.Contains(firstBootLabels, p.Name) {
			numbers[p.Name] = p.Index
		}
	}
	if numbers[disk.LabelState] == 0 || numbers[disk.LabelBackup] == 0 {
		return nil, nil, nil, errors.New("keycustody: the disk has no state and backup partitions")
	}
	return b.volumes(numbers)
}

func (b *BootDisk) volumes(numbers map[string]int) (Volume, Volume, KeyfileStore, error) {
	vol := func(label, mapped, target string) *LUKSVolume {
		return &LUKSVolume{
			Device: &luks.Device{Path: b.partition(numbers[label]), Runner: b.Cryptsetup, PBKDFArgs: b.PBKDFArgs},
			Name:   mapped, Target: target, Mounter: b.Mounter,
		}
	}
	var kf KeyfileStore
	if n := numbers[disk.LabelKeyfile]; n != 0 {
		kf = FileKeyfile{Path: b.partition(n)}
	}
	return vol(disk.LabelState, stateMapped, StateTarget), vol(disk.LabelBackup, backupMapped, BackupTarget), kf, nil
}

// partition is the kernel's name for partition n: vda5, but nvme0n1p5 and
// mmcblk0p5 when the disk's name ends in a digit.
func (b *BootDisk) partition(n int) string {
	if unicode.IsDigit(rune(b.Path[len(b.Path)-1])) {
		return fmt.Sprintf("%sp%d", b.Path, n)
	}
	return fmt.Sprintf("%s%d", b.Path, n)
}

// blkpg is the BLKPG ioctl request (linux/fs.h: _IO(0x12, 105)).
const blkpg = 0x1269

// tellKernel drops the stale partitions from the kernel's view and adds
// the planned ones, then waits for their device nodes.
func (b *BootDisk) tellKernel(stale []int, plan []disk.Partition) error {
	st, err := os.Stat(b.Path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeDevice == 0 {
		return nil
	}
	f, err := os.Open(b.Path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	ioctl := func(op int32, p unix.BlkpgPartition) error {
		arg := unix.BlkpgIoctlArg{Op: op, Datalen: int32(unsafe.Sizeof(p)), Data: (*byte)(unsafe.Pointer(&p))}     // #nosec G103 G115 -- the ioctl's own argument layout
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), blkpg, uintptr(unsafe.Pointer(&arg))); errno != 0 { // #nosec G103 -- as above
			return errno
		}
		return nil
	}
	for _, n := range stale {
		if err := ioctl(unix.BLKPG_DEL_PARTITION, unix.BlkpgPartition{Pno: int32(n)}); err != nil && !errors.Is(err, unix.ENXIO) { // #nosec G115 -- a GPT partition number
			return fmt.Errorf("keycustody: the kernel kept partition %d of %s: %w", n, b.Path, err)
		}
	}
	for _, q := range plan {
		if err := ioctl(unix.BLKPG_ADD_PARTITION, unix.BlkpgPartition{Start: q.Start, Length: q.Size, Pno: int32(q.Number)}); err != nil { // #nosec G115 -- as above
			return fmt.Errorf("keycustody: the kernel didn't add partition %d of %s: %w", q.Number, b.Path, err)
		}
	}
	for _, q := range plan {
		p := b.partition(q.Number)
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(p); err == nil {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("keycustody: %s didn't appear", p)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	return nil
}

// Ext4 makes and mounts the volumes' ext4 filesystems.
type Ext4 struct {
	// MkfsRunner runs the image's static mkfs.ext4 (on the box, through
	// init's reaper, which owns every child's exit).
	MkfsRunner luks.Runner
}

// Mkfs makes the filesystem on device.
func (e Ext4) Mkfs(ctx context.Context, device string) error {
	_, stderr, err := e.MkfsRunner.Run(ctx, nil, "-q", "-F", "-t", "ext4", device)
	if err != nil {
		return fmt.Errorf("%w (%s)", err, stderr)
	}
	return nil
}

// Mount mounts device at target, nosuid and nodev.
func (e Ext4) Mount(_ context.Context, device, target string) error {
	if err := unix.Mount(device, target, "ext4", unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return fmt.Errorf("keycustody: mount %s on %s: %w", device, target, err)
	}
	return nil
}
