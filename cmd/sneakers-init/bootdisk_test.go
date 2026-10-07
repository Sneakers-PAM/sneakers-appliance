// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestDiskOf(t *testing.T) {
	for part, want := range map[string]string{
		"/dev/sda1":      "/dev/sda",
		"/dev/vda12":     "/dev/vda",
		"/dev/nvme0n1p1": "/dev/nvme0n1",
		"/dev/mmcblk0p2": "/dev/mmcblk0",
	} {
		if got := diskOf(part); got != want {
			t.Errorf("%s: got %s want %s", part, got, want)
		}
	}
}
