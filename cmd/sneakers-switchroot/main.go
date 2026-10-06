// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0
// Copyright The CryptOS Authors.

// Command sneakers-switchroot is the /init of the UKI's initrd: it opens the
// root the signed command line names with dm-verity and switch_roots into
// /sbin/init. See internal/switchroot.
//
// It only runs as PID 1 on Linux. On failure there's nowhere to go, so it
// panics: PID 1 dying panics the kernel, which reboots after panic=10, and
// boot counting moves the box back to the previous release.
package main

import (
	"os"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/switchroot"
)

func main() {
	if err := switchroot.Run(switchroot.NewSystem(), os.Environ()); err != nil {
		panic("sneakers-switchroot: " + codes.Describe(err))
	}
}
