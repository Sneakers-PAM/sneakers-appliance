// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package keycustody

import (
	"context"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A power cut soon after an update must not leave a file the box had
// already counted as written empty. Containerd records an image's layer as
// unpacked with an fsync of its own database, which with ext4's delayed
// allocation doesn't carry the layer's files: after the cut a container's
// binary is empty and its start fails with "exec format error". Mounted
// nodelalloc (in the default data=ordered mode), each journal commit
// writes the data of the files it covers first, so any fsync on the
// volume also makes what was written before it durable.
func TestTheVolumesMountWithoutDelayedAllocation(t *testing.T) {
	old := mountFS
	t.Cleanup(func() { mountFS = old })
	var got struct {
		source, target, fstype, data string
		flags                        uintptr
	}
	mountFS = func(source, target, fstype string, flags uintptr, data string) error {
		got.source, got.target, got.fstype, got.flags, got.data = source, target, fstype, flags, data
		return nil
	}
	if err := (Ext4{}).Mount(context.Background(), "/dev/mapper/sneakers-state", "/var/lib"); err != nil {
		t.Fatal(err)
	}
	if got.source != "/dev/mapper/sneakers-state" || got.target != "/var/lib" || got.fstype != "ext4" {
		t.Fatalf("mounted %s on %s as %s", got.source, got.target, got.fstype)
	}
	if got.flags != unix.MS_NOSUID|unix.MS_NODEV {
		t.Errorf("flags %#x, want nosuid and nodev", got.flags)
	}
	opts := strings.Split(got.data, ",")
	if !slices.Contains(opts, "nodelalloc") {
		t.Errorf("options %q: no nodelalloc", got.data)
	}
	for _, o := range opts {
		if strings.HasPrefix(o, "data=") && o != "data=ordered" {
			t.Errorf("options %q: %s, want the ordered data mode", got.data, o)
		}
	}
}
