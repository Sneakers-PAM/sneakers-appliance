// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package power_test

import (
	"slices"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/power"
)

const mounts = `/dev/mapper/root-verity / squashfs ro,relatime 0 0
proc /proc proc rw,nosuid,nodev 0 0
/dev/sda1 /run/sneakers/esp vfat rw,nosuid,nodev,noexec 0 0
/dev/mapper/sneakers-state /var/lib/sneakers ext4 rw,relatime 0 0
/dev/mapper/sneakers-state /var/lib/k0s ext4 rw,relatime 0 0
tmpfs /var/lib/k0s/kubelet/pods/a\040b/volumes tmpfs rw 0 0
/dev/mapper/sneakers-backup /var/lib/sneakers/backup ext4 rw,relatime 0 0
`

func TestVolumeMountsAreUnmountedDeepestFirst(t *testing.T) {
	targets, mappings := power.VolumeMounts(mounts)
	want := []string{"/var/lib/k0s/kubelet/pods/a b/volumes", "/var/lib/sneakers/backup", "/var/lib/sneakers", "/var/lib/k0s"}
	if !slices.Equal(targets, want) {
		t.Fatalf("targets %v", targets)
	}
	if !slices.Equal(mappings, []string{"sneakers-backup", "sneakers-state"}) {
		t.Fatalf("mappings %v", mappings)
	}
}
