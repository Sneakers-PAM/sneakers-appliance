// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"strings"
	"testing"
)

// A mount flag spelled in the data string makes tmpfs refuse the mount
// (EINVAL), which left /run read-only and stopped init before the service
// table.
func TestEarlyMountsPassFlagsAsFlagsNotData(t *testing.T) {
	flags := map[string]bool{"nosuid": true, "nodev": true, "noexec": true, "ro": true, "rw": true, "noatime": true, "relatime": true}
	for _, m := range earlyMounts {
		for _, opt := range strings.Split(m.data, ",") {
			key, _, _ := strings.Cut(opt, "=")
			if flags[key] {
				t.Errorf("%s (%s): %q is a mount flag in the data %q", m.dst, m.fstype, key, m.data)
			}
		}
	}
}
