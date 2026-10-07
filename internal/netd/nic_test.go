// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

// The interfaces k0s, the CNI and the kernel make: up, named to sort
// first, and with no bus behind them.
var virtual = []netd.Link{
	{Name: "cni0", MAC: "0a:00:00:00:00:01", Up: true, Driver: ""},
	{Name: "dummy0", MAC: "0a:00:00:00:00:02", Up: true},
	{Name: "kube-bridge", MAC: "0a:00:00:00:00:03", Up: true},
	{Name: "sneakers0", MAC: "0a:00:00:00:00:04", Up: true},
	{Name: "veth1a2b3c", MAC: "0a:00:00:00:00:05", Up: true},
	{Name: "flannel.1", MAC: "0a:00:00:00:00:06", Up: true},
	{Name: "tun0", Up: true},
	{Name: "wg0", Up: true},
}

func withVirtual(links ...netd.Link) []netd.Link {
	return append(append([]netd.Link{}, virtual...), links...)
}

func TestFirstStartPicksThePhysicalNICByBusOrderNotName(t *testing.T) {
	// ens9 sorts before eth5 by name but sits later on the bus; ens3 is
	// first on the bus but has no link.
	ens3 := netd.Link{Name: "ens3", MAC: "52:54:00:00:00:03", Up: false, Bus: "pci0000:00/0000:00:02.0"}
	eth5 := netd.Link{Name: "eth5", MAC: "52:54:00:00:00:05", Up: true, Bus: "pci0000:00/0000:00:05.0/virtio2"}
	ens9 := netd.Link{Name: "ens9", MAC: "52:54:00:00:00:09", Up: true, Bus: "pci0000:00/0000:00:09.0"}
	b := newBox(t, withVirtual(ens9, ens3, eth5)...)
	d := b.start()
	if s, _ := d.Get(); s.Management.Name != "eth5" {
		t.Fatalf("management on %q", s.Management.Name)
	}
}

func TestFirstStartTakesTheFirstPhysicalNICWhenNoneHasALink(t *testing.T) {
	a := netd.Link{Name: "eth1", MAC: "52:54:00:00:00:02", Bus: "pci0000:00/0000:00:06.0"}
	c := netd.Link{Name: "eth0", MAC: "52:54:00:00:00:01", Bus: "pci0000:00/0000:00:07.0"}
	b := newBox(t, withVirtual(c, a)...)
	d := b.start()
	if s, _ := d.Get(); s.Management.Name != "eth1" {
		t.Fatalf("management on %q", s.Management.Name)
	}
}

func TestFirstStartWithOnlyVirtualInterfacesWaitsForANIC(t *testing.T) {
	b := newBox(t, virtual...)
	d := b.start()
	if s, _ := d.Get(); s.Management.Name != "" {
		t.Fatalf("management on %q", s.Management.Name)
	}
}

func TestInterfacesListOnlyPhysicalNICsByBusThenMAC(t *testing.T) {
	// Two ports of one device share its bus path; the MAC orders them.
	p2 := netd.Link{Name: "enp1s0d1", MAC: "52:54:00:00:00:22", Up: true, Bus: "pci0000:00/0000:00:1c.0/0000:01:00.0"}
	p1 := netd.Link{Name: "enp1s0", MAC: "52:54:00:00:00:21", Up: true, Bus: "pci0000:00/0000:00:1c.0/0000:01:00.0"}
	b := newBox(t, withVirtual(netd.Link{Name: "lo", Up: true}, eth1, p2, p1, eth0)...)
	d := b.start()
	got, err := d.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, l := range got {
		names = append(names, l.Name)
	}
	want := []string{"eth0", "eth1", "enp1s0", "enp1s0d1"}
	if len(names) != len(want) {
		t.Fatalf("interfaces %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("interfaces %v, want %v", names, want)
		}
	}
}

func TestSetRefusesAVirtualInterface(t *testing.T) {
	b := newBox(t, withVirtual(eth0)...)
	d := b.start()
	for _, name := range []string{"cni0", "dummy0", "kube-bridge", "veth1a2b3c"} {
		_, err := d.Set(network.Defaults(name))
		if !codes.Is(err, codes.NetInvalid) || network.Field(err) != "management.name" {
			t.Errorf("Set on %s: %v", name, err)
		}
	}
}
