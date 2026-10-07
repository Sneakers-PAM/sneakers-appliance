// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "strings"

// diskOf is the disk a partition device belongs to: /dev/sda1 is on
// /dev/sda, /dev/nvme0n1p1 on /dev/nvme0n1.
func diskOf(part string) string {
	d := strings.TrimRight(part, "0123456789")
	if t, ok := strings.CutSuffix(d, "p"); ok && t != "" && t[len(t)-1] >= '0' && t[len(t)-1] <= '9' {
		return t
	}
	return d
}
