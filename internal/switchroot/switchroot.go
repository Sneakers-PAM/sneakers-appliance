// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0
// Copyright The CryptOS Authors.

// Package switchroot is the initrd shim the UKI starts: it finds the root
// the signed command line names, opens it with dm-verity, mounts it
// read-only and switch_roots into /sbin/init.
//
// Ported from CryptOS-PKI's internal/switchroot (Apache-2.0). There the root
// rides inside the initrd; here it's a verity-protected partition, or on the
// install medium a root image file opened through a loop device the same
// way.
package switchroot

import (
	"errors"
	"fmt"
	"io/fs"
	"strconv"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bootcmd"
)

// Paths the shim uses.
const (
	NewRoot              = "/sysroot"
	InitPath             = "/sbin/init"
	InstallMount         = "/run/sneakers-install"
	Veritysetup          = "/usr/sbin/veritysetup"
	VerityName           = "sneakers-root"
	VerityDevice         = "/dev/mapper/" + VerityName
	msRDONLY     uintptr = 1 << 0
	msMOVE       uintptr = 1 << 13
	mntDETACH            = 2
)

// System is the set of OS operations the pivot needs, injected so the
// sequence tests without touching real mounts.
type System interface {
	Mkdir(path string, perm uint32) error
	Mount(source, target, fstype string, flags uintptr, data string) error
	Unmount(target string, flags int) error
	ReadFile(path string) ([]byte, error)
	// Partitions lists the GPT partitions of every disk and every whole
	// device that carries an ISO 9660 volume.
	Partitions() ([]Partition, error)
	// AttachLoop binds backingFile read-only to a free loop device.
	AttachLoop(backingFile string) (string, error)
	// Run runs a helper (veritysetup) to completion.
	Run(argv []string) error
	Chdir(dir string) error
	Chroot(dir string) error
	// Exec replaces the process image; on success it doesn't return.
	Exec(argv0 string, argv, envv []string) error
	Logf(format string, args ...any)
}

func mkdir(sys System, p string) error {
	if err := sys.Mkdir(p, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("switchroot: mkdir %s: %w", p, err)
	}
	return nil
}

// Run performs the pivot:
//
//  1. mount /dev, /proc and /sys, and read the command line;
//  2. find the root (FindRoot); from the install medium, mount it and
//     attach the root image file to a loop device;
//  3. veritysetup open with the signed root hash and offset, panicking on
//     corruption;
//  4. mount the verity device read-only at /sysroot, move /dev into it,
//     and switch_root into /sbin/init.
//
// On success Exec doesn't return; any return is an error.
func Run(sys System, env []string) error {
	for _, m := range []struct{ src, dst, fstype, data string }{
		{"devtmpfs", "/dev", "devtmpfs", "mode=0755"},
		{"proc", "/proc", "proc", ""},
		{"sysfs", "/sys", "sysfs", ""},
	} {
		if err := mkdir(sys, m.dst); err != nil {
			return err
		}
		if err := sys.Mount(m.src, m.dst, m.fstype, 0, m.data); err != nil {
			return fmt.Errorf("switchroot: mount %s: %w", m.dst, err)
		}
	}
	cmd, err := sys.ReadFile("/proc/cmdline")
	if err != nil {
		return fmt.Errorf("switchroot: read the command line: %w", err)
	}
	params, err := bootcmd.Parse(string(cmd))
	if err != nil {
		return fmt.Errorf("switchroot: %w", err)
	}
	parts, err := sys.Partitions()
	if err != nil {
		return fmt.Errorf("switchroot: list partitions: %w", err)
	}
	root, err := FindRoot(string(cmd), parts)
	if err != nil {
		return err
	}
	dev := root.Device
	if root.Install() {
		sys.Logf("sneakers-switchroot: install mode, root image %s on %s", root.ImageFile, root.Device)
		if err := mkdir(sys, InstallMount); err != nil {
			return err
		}
		if err := sys.Mount(root.Device, InstallMount, "iso9660", msRDONLY, ""); err != nil {
			return fmt.Errorf("switchroot: mount the install medium %s: %w", root.Device, err)
		}
		if dev, err = sys.AttachLoop(InstallMount + "/" + root.ImageFile); err != nil {
			return fmt.Errorf("switchroot: attach the root image: %w", err)
		}
	} else {
		sys.Logf("sneakers-switchroot: root %s (%s)", root.Device, root.Label)
	}
	if err := sys.Run([]string{Veritysetup, "open", dev, VerityName, dev, params.RootHash,
		"--hash-offset=" + strconv.FormatInt(params.HashOffset, 10), "--panic-on-corruption"}); err != nil {
		return fmt.Errorf("switchroot: veritysetup open %s: %w", dev, err)
	}
	if err := mkdir(sys, NewRoot); err != nil {
		return err
	}
	if err := sys.Mount(VerityDevice, NewRoot, "squashfs", msRDONLY, ""); err != nil {
		return fmt.Errorf("switchroot: mount %s on %s: %w", VerityDevice, NewRoot, err)
	}
	// init mounts its own /proc and /sys; /dev moves across so the verity
	// device node stays reachable.
	for _, p := range []string{"/proc", "/sys"} {
		if err := sys.Unmount(p, mntDETACH); err != nil {
			return fmt.Errorf("switchroot: unmount %s: %w", p, err)
		}
	}
	if err := sys.Mount("/dev", NewRoot+"/dev", "", msMOVE, ""); err != nil {
		return fmt.Errorf("switchroot: move /dev: %w", err)
	}
	if err := sys.Chdir(NewRoot); err != nil {
		return fmt.Errorf("switchroot: chdir %s: %w", NewRoot, err)
	}
	if err := sys.Mount(".", "/", "", msMOVE, ""); err != nil {
		return fmt.Errorf("switchroot: move mount to /: %w", err)
	}
	if err := sys.Chroot("."); err != nil {
		return fmt.Errorf("switchroot: chroot: %w", err)
	}
	if err := sys.Chdir("/"); err != nil {
		return fmt.Errorf("switchroot: chdir /: %w", err)
	}
	if err := sys.Exec(InitPath, []string{InitPath}, env); err != nil {
		return fmt.Errorf("switchroot: exec %s: %w", InitPath, err)
	}
	return errors.New("switchroot: exec returned without error")
}
