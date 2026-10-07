// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package factoryreset

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// blkpg is the BLKPG ioctl request (linux/fs.h: _IO(0x12, 105)).
const blkpg = 0x1269

// KernelForget returns a Notify for the disk at dev: it drops each
// partition from the kernel's view with BLKPG_DEL_PARTITION, which works
// while the ESP on the same disk stays mounted. A partition the kernel no
// longer has (a resume) is skipped.
func KernelForget(dev string) func(numbers []int) error {
	return func(numbers []int) error {
		f, err := os.Open(dev) // #nosec G304 -- the boot disk's device node
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		for _, n := range numbers {
			p := unix.BlkpgPartition{Pno: int32(n)}                                                                                      // #nosec G115 -- a GPT partition number
			arg := unix.BlkpgIoctlArg{Op: unix.BLKPG_DEL_PARTITION, Datalen: int32(unsafe.Sizeof(p)), Data: (*byte)(unsafe.Pointer(&p))} // #nosec G103 G115 -- the ioctl's own argument layout
			_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), blkpg, uintptr(unsafe.Pointer(&arg)))                                    // #nosec G103 -- as above
			if errno != 0 && !errors.Is(errno, unix.ENXIO) {
				return fmt.Errorf("factory reset: the kernel kept partition %d of %s: %w", n, dev, errno)
			}
		}
		return nil
	}
}
