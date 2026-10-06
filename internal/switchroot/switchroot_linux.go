// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0
// Copyright The CryptOS Authors.

//go:build linux

package switchroot

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"

	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/partition/gpt"
	"golang.org/x/sys/unix"
)

// loopMajor is the device-node major number for loop devices.
const loopMajor = 7

type linuxSystem struct{}

// NewSystem returns the real Linux System.
func NewSystem() System { return linuxSystem{} }

func (linuxSystem) Mkdir(path string, perm uint32) error { return unix.Mkdir(path, perm) }
func (linuxSystem) Mount(source, target, fstype string, flags uintptr, data string) error {
	return unix.Mount(source, target, fstype, flags, data)
}
func (linuxSystem) Unmount(target string, flags int) error { return unix.Unmount(target, flags) }
func (linuxSystem) ReadFile(path string) ([]byte, error)   { return os.ReadFile(path) } // #nosec G304 -- fixed paths under /proc
func (linuxSystem) Chdir(dir string) error                 { return unix.Chdir(dir) }
func (linuxSystem) Chroot(dir string) error                { return unix.Chroot(dir) }
func (linuxSystem) Exec(argv0 string, argv, envv []string) error {
	return unix.Exec(argv0, argv, envv)
}

func (linuxSystem) Logf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func (linuxSystem) Run(argv []string) error {
	cmd := exec.Command(argv[0], argv[1:]...) // #nosec G204 -- the fixed veritysetup path with the signed parameters
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

// Partitions reads the GPT of every disk under /sys/block, and notes every
// whole device whose first ISO 9660 descriptor carries a volume label.
func (linuxSystem) Partitions() ([]Partition, error) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}
	var out []Partition
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "dm-") {
			continue
		}
		dev := "/dev/" + name
		if label := isoLabel(dev); label != "" {
			out = append(out, Partition{Device: dev, VolumeLabel: label})
		}
		out = append(out, gptPartitions(name)...)
	}
	return out, nil
}

func gptPartitions(name string) []Partition {
	d, err := diskfs.Open("/dev/"+name, diskfs.WithOpenMode(diskfs.ReadOnly))
	if err != nil {
		return nil
	}
	defer func() { _ = d.Close() }()
	t, err := d.GetPartitionTable()
	if err != nil {
		return nil
	}
	table, ok := t.(*gpt.Table)
	if !ok {
		return nil
	}
	var out []Partition
	for _, p := range table.Partitions {
		if p.Type == gpt.Unused {
			continue
		}
		out = append(out, Partition{Device: partDevice(name, p.Index), Label: p.Name, PartUUID: strings.ToLower(p.GUID)})
	}
	return out
}

// partDevice is the kernel's name for partition n of disk: sda2, but
// nvme0n1p2 and mmcblk0p2 when the disk name ends in a digit.
func partDevice(disk string, n int) string {
	if r := rune(disk[len(disk)-1]); unicode.IsDigit(r) {
		return fmt.Sprintf("/dev/%sp%d", disk, n)
	}
	return fmt.Sprintf("/dev/%s%d", disk, n)
}

// isoLabel reads the volume identifier of an ISO 9660 primary volume
// descriptor at sector 16, or returns "".
func isoLabel(dev string) string {
	f, err := os.Open(dev) // #nosec G304 -- a block device under /dev named by /sys/block
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	var pvd [2048]byte
	if _, err := f.ReadAt(pvd[:], 16*2048); err != nil {
		return ""
	}
	if pvd[0] != 1 || string(pvd[1:6]) != "CD001" {
		return ""
	}
	return strings.TrimRight(string(pvd[40:72]), " \x00")
}

// AttachLoop binds backingFile (read-only) to the first free loop device,
// creating the device node if devtmpfs hasn't yet.
func (linuxSystem) AttachLoop(backingFile string) (string, error) {
	backingFd, err := unix.Open(backingFile, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open backing file: %w", err)
	}
	defer func() { _ = unix.Close(backingFd) }()
	ctrl, err := unix.Open("/dev/loop-control", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open /dev/loop-control: %w", err)
	}
	defer func() { _ = unix.Close(ctrl) }()
	num, err := unix.IoctlRetInt(ctrl, unix.LOOP_CTL_GET_FREE)
	if err != nil {
		return "", fmt.Errorf("LOOP_CTL_GET_FREE: %w", err)
	}
	dev := filepath.Join("/dev", fmt.Sprintf("loop%d", num))
	node := int(unix.Mkdev(loopMajor, uint32(num))) // #nosec G115 -- loop numbers are small and non-negative
	if err := unix.Mknod(dev, unix.S_IFBLK|0o600, node); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("mknod %s: %w", dev, err)
	}
	loopFd, err := unix.Open(dev, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", dev, err)
	}
	defer func() { _ = unix.Close(loopFd) }()
	if err := unix.IoctlSetInt(loopFd, unix.LOOP_SET_FD, backingFd); err != nil {
		return "", fmt.Errorf("LOOP_SET_FD: %w", err)
	}
	return dev, nil
}
