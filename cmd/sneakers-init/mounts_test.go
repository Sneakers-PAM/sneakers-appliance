// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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

// Without devpts on /dev/pts, opening /dev/ptmx fails: sshd refuses every
// PTY request, the closed shell runs on pipes and never shows its menu,
// and the root shell can't open a terminal.
func TestEarlyMountsMountDevptsUnderDev(t *testing.T) {
	dev, pts := -1, -1
	for i, m := range earlyMounts {
		switch m.dst {
		case "/dev":
			dev = i
		case "/dev/pts":
			pts = i
			if m.fstype != "devpts" {
				t.Errorf("/dev/pts is %s, want devpts", m.fstype)
			}
			if m.flags&unix.MS_NODEV != 0 {
				t.Error("/dev/pts is mounted nodev, so its terminals can't be opened")
			}
			if m.flags&unix.MS_NOSUID == 0 || m.flags&unix.MS_NOEXEC == 0 {
				t.Errorf("/dev/pts flags %#x, want nosuid and noexec", m.flags)
			}
			for _, want := range []string{"mode=0620", "ptmxmode=0666"} {
				if !slices.Contains(strings.Split(m.data, ","), want) {
					t.Errorf("/dev/pts data %q lacks %s", m.data, want)
				}
			}
		}
	}
	if pts < 0 {
		t.Fatal("no devpts mount on /dev/pts")
	}
	if pts < dev {
		t.Error("/dev/pts is mounted before /dev")
	}
}
