// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package network_test

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

func TestWireRoundTrip(t *testing.T) {
	s := with(func(s *network.Settings) {
		staticV4("192.0.2.10/24", "192.0.2.1")(s)
		staticV6("2001:db8::10/64", "fe80::1")(s)
		s.Service = &network.Interface{Name: "eth1", IPv4: network.Family4{Mode: network.V4DHCP}, IPv6: network.Family6{Mode: network.V6DHCPv6}}
		s.Hostname = "appliance.example.org"
		s.DNS = addrs("192.0.2.53")
		s.NTP = []string{"ntp.example.org"}
		s.AllowList = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	})
	got, err := network.FromWire(network.ToWire(s))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, s) {
		t.Fatalf("round trip\n got %+v\nwant %+v", got, s)
	}
}

func TestFromWireNamesTheField(t *testing.T) {
	w := network.ToWire(base())
	w.Management.Ipv4.Address = "192.0.2.10"
	_, err := network.FromWire(w)
	assertFieldErr(t, err, "NET_INVALID", "management.ipv4.address")

	w = network.ToWire(base())
	w.Dns = []string{"dns.example.org"}
	_, err = network.FromWire(w)
	assertFieldErr(t, err, "NET_INVALID", "dns[0]")
}
