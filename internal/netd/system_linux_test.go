// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netd_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/netd"
)

// An interface's bus is its device under /sys/devices; lo, which every
// namespace has, stands in for a NIC behind a fake sysfs here.
func TestLinksReadTheBusFromSysfs(t *testing.T) {
	sys := t.TempDir()
	dev := filepath.Join(sys, "devices", "pci0000:00", "0000:00:1f.6")
	if err := os.MkdirAll(dev, 0o755); err != nil {
		t.Fatal(err)
	}
	ifDir := filepath.Join(sys, "class", "net", "lo")
	if err := os.MkdirAll(ifDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../devices/pci0000:00/0000:00:1f.6", filepath.Join(ifDir, "device")); err != nil {
		t.Fatal(err)
	}
	links, err := netd.Linux{Sys: sys}.Links()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range links {
		switch {
		case l.Name == "lo":
			found = true
			if l.Bus != "pci0000:00/0000:00:1f.6" || !l.Physical() {
				t.Fatalf("lo %+v", l)
			}
		case l.Physical():
			t.Fatalf("%s has a bus without a device link: %+v", l.Name, l)
		}
	}
	if !found {
		t.Fatal("no lo")
	}
}
