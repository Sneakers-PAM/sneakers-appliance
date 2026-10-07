// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package network_test

import (
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

func TestSettingsFileRoundTrips(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings", "network.yaml")
	for _, s := range []network.Settings{
		network.Defaults("eth0"),
		func() network.Settings {
			s := network.Defaults("eth0")
			s.Management.IPv4 = network.Family4{Mode: network.V4Static, Address: netip.MustParsePrefix("192.0.2.10/24"), Gateway: netip.MustParseAddr("192.0.2.1")}
			s.Service = &network.Interface{Name: "eth1", IPv4: network.Family4{Mode: network.V4DHCP}, IPv6: network.Family6{Mode: network.V6Off}}
			s.DNS = []netip.Addr{netip.MustParseAddr("2001:db8::53")}
			s.AllowList = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
			s.NTP = []string{"time.example.org"}
			return s
		}(),
	} {
		if err := network.WriteFile(p, s); err != nil {
			t.Fatal(err)
		}
		got, err := network.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, s) {
			t.Fatalf("read back\n%+v\nwrote\n%+v", got, s)
		}
	}
}
