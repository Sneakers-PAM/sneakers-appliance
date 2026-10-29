// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package vports_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/vports"
)

// port adds a virtio port to a fake /sys/class/virtio-ports, as the kernel
// shows it: the name file ends in a newline, and a port the host didn't
// name has an empty one.
func port(t *testing.T, sys, dev, name string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(sys, dev), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sys, dev, "name"), []byte(name+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func target(t *testing.T, link string) string {
	t.Helper()
	got, err := os.Readlink(link)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestLinkNamesEachPortLikeUdev(t *testing.T) {
	sys, dev := t.TempDir(), t.TempDir()
	port(t, sys, "vport1p1", "org.qemu.guest_agent.0")
	port(t, sys, "vport2p1", "")
	if err := vports.Link(sys, dev); err != nil {
		t.Fatal(err)
	}
	if got := target(t, filepath.Join(dev, "virtio-ports", "org.qemu.guest_agent.0")); got != "../vport1p1" {
		t.Fatalf("link points at %q", got)
	}
	entries, err := os.ReadDir(filepath.Join(dev, "virtio-ports"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("an unnamed port was linked: %v %v", entries, err)
	}
}

func TestLinkFollowsAPortThatMoved(t *testing.T) {
	sys, dev := t.TempDir(), t.TempDir()
	port(t, sys, "vport1p1", "org.qemu.guest_agent.0")
	if err := vports.Link(sys, dev); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(sys, "vport1p1")); err != nil {
		t.Fatal(err)
	}
	port(t, sys, "vport3p1", "org.qemu.guest_agent.0")
	if err := vports.Link(sys, dev); err != nil {
		t.Fatal(err)
	}
	if got := target(t, filepath.Join(dev, "virtio-ports", "org.qemu.guest_agent.0")); got != "../vport3p1" {
		t.Fatalf("link points at %q", got)
	}
}

func TestLinkDropsAPortThatWentAway(t *testing.T) {
	sys, dev := t.TempDir(), t.TempDir()
	port(t, sys, "vport1p1", "org.qemu.guest_agent.0")
	if err := vports.Link(sys, dev); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(sys, "vport1p1")); err != nil {
		t.Fatal(err)
	}
	if err := vports.Link(sys, dev); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dev, "virtio-ports", "org.qemu.guest_agent.0")); !os.IsNotExist(err) {
		t.Fatalf("the link to a gone port stayed: %v", err)
	}
}

// A box without virtio-serial (VMware, bare metal) has no virtio-ports
// class at all.
func TestLinkWithoutTheClassIsNothingToDo(t *testing.T) {
	dev := t.TempDir()
	if err := vports.Link(filepath.Join(t.TempDir(), "missing"), dev); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dev, "virtio-ports")); !os.IsNotExist(err) {
		t.Fatalf("made %s without any port: %v", filepath.Join(dev, "virtio-ports"), err)
	}
}

// A host-chosen name that would leave the directory is never linked.
func TestLinkRefusesANameWithASlash(t *testing.T) {
	sys, dev := t.TempDir(), t.TempDir()
	port(t, sys, "vport1p1", "../../etc/evil")
	port(t, sys, "vport1p2", "..")
	if err := vports.Link(sys, dev); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(dev, "virtio-ports"))
	if len(entries) != 0 {
		t.Fatalf("linked %v", entries)
	}
}
