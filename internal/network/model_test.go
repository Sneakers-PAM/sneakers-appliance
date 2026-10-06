// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package network_test

import (
	"net/netip"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

func assertFieldErr(t *testing.T, err error, symbol, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %s on %s", symbol, field)
	}
	c, ok := codes.Of(err)
	if !ok || codes.Symbol(c) != symbol {
		t.Fatalf("got %v, want %s", err, symbol)
	}
	if got := network.Field(err); got != field {
		t.Fatalf("field %q, want %q (%v)", got, field, err)
	}
}

func base() network.Settings { return network.Defaults("eth0") }

func with(mut func(*network.Settings)) network.Settings {
	s := base()
	mut(&s)
	return s
}

func staticV4(addr, gw string) func(*network.Settings) {
	return func(s *network.Settings) {
		s.Management.IPv4 = network.Family4{Mode: network.V4Static}
		if addr != "" {
			s.Management.IPv4.Address = netip.MustParsePrefix(addr)
		}
		if gw != "" {
			s.Management.IPv4.Gateway = netip.MustParseAddr(gw)
		}
	}
}

func staticV6(addr, gw string) func(*network.Settings) {
	return func(s *network.Settings) {
		s.Management.IPv6 = network.Family6{Mode: network.V6Static}
		if addr != "" {
			s.Management.IPv6.Address = netip.MustParsePrefix(addr)
		}
		if gw != "" {
			s.Management.IPv6.Gateway = netip.MustParseAddr(gw)
		}
	}
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func TestValidateAccepts(t *testing.T) {
	good := map[string]network.Settings{
		"defaults":  base(),
		"static v4": with(staticV4("192.0.2.10/24", "192.0.2.1")),
		"static v6 with a link-local gateway": with(func(s *network.Settings) {
			staticV6("2001:db8::10/64", "fe80::1")(s)
			s.Management.IPv4.Mode = network.V4Off
		}),
		"v6 only slaac":      with(func(s *network.Settings) { s.Management.IPv4.Mode = network.V4Off }),
		"dhcpv6":             with(func(s *network.Settings) { s.Management.IPv6.Mode = network.V6DHCPv6 }),
		"point to point /31": with(staticV4("192.0.2.0/31", "")),
		"everything set": with(func(s *network.Settings) {
			staticV4("192.0.2.10/24", "192.0.2.1")(s)
			s.Service = &network.Interface{Name: "eth1", IPv4: network.Family4{Mode: network.V4DHCP}, IPv6: network.Family6{Mode: network.V6Off}}
			s.Hostname = "appliance.example.org"
			s.DNS = addrs("192.0.2.53", "2001:db8::53")
			s.Search = []string{"example.org"}
			s.NTP = []string{"ntp.example.org", "192.0.2.123", "2001:db8::123"}
			s.AllowList = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}
			s.TimeZone = "Europe/Paris"
			s.HTTPSProxy = "http://proxy.example.org:3128"
		}),
	}
	for name, s := range good {
		t.Run(name, func(t *testing.T) {
			if err := network.Validate(s); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	bad := []struct {
		name, field string
		s           network.Settings
	}{
		{"no interface", "management.name", with(func(s *network.Settings) { s.Management.Name = "" })},
		{"no family on mgmt", "management.ipv4", with(func(s *network.Settings) {
			s.Management.IPv4.Mode, s.Management.IPv6.Mode = network.V4Off, network.V6Off
		})},
		{"unknown v4 mode", "management.ipv4.mode", with(func(s *network.Settings) { s.Management.IPv4.Mode = "bootp" })},
		{"unknown v6 mode", "management.ipv6.mode", with(func(s *network.Settings) { s.Management.IPv6.Mode = "ra" })},
		{"static without prefix", "management.ipv4.address", with(staticV4("", ""))},
		{"static v4 given a v6 address", "management.ipv4.address", with(staticV4("2001:db8::10/64", ""))},
		{"static on the network address", "management.ipv4.address", with(staticV4("192.0.2.0/24", ""))},
		{"static on the broadcast address", "management.ipv4.address", with(staticV4("192.0.2.255/24", ""))},
		{"loopback", "management.ipv4.address", with(staticV4("127.0.0.2/8", ""))},
		{"gateway outside the subnet", "management.ipv4.gateway", with(staticV4("192.0.2.10/24", "198.51.100.1"))},
		{"gateway is the address", "management.ipv4.gateway", with(staticV4("192.0.2.10/24", "192.0.2.10"))},
		{"dhcp with an address", "management.ipv4.address", with(func(s *network.Settings) {
			s.Management.IPv4.Address = netip.MustParsePrefix("192.0.2.10/24")
		})},
		{"static v6 without prefix", "management.ipv6.address", with(staticV6("", ""))},
		{"static v6 link-local", "management.ipv6.address", with(staticV6("fe80::10/64", ""))},
		{"v6 gateway elsewhere", "management.ipv6.gateway", with(staticV6("2001:db8::10/64", "2001:db8:1::1"))},
		{"service on the management nic", "service.name", with(func(s *network.Settings) {
			s.Service = &network.Interface{Name: "eth0", IPv4: network.Family4{Mode: network.V4DHCP}, IPv6: network.Family6{Mode: network.V6Off}}
		})},
		{"service with no family", "service.ipv4", with(func(s *network.Settings) {
			s.Service = &network.Interface{Name: "eth1", IPv4: network.Family4{Mode: network.V4Off}, IPv6: network.Family6{Mode: network.V6Off}}
		})},
		{"short hostname", "hostname", with(func(s *network.Settings) { s.Hostname = "appliance" })},
		{"bad hostname", "hostname", with(func(s *network.Settings) { s.Hostname = "-bad.example.org" })},
		{"four DNS servers", "dns", with(func(s *network.Settings) { s.DNS = addrs("192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::1") })},
		{"unspecified DNS server", "dns[0]", with(func(s *network.Settings) { s.DNS = addrs("0.0.0.0") })},
		{"bad search domain", "search[0]", with(func(s *network.Settings) { s.Search = []string{"not a domain"} })},
		{"five NTP servers", "ntp", with(func(s *network.Settings) {
			s.NTP = []string{"a.example.org", "b.example.org", "c.example.org", "d.example.org", "e.example.org"}
		})},
		{"bad NTP server", "ntp[0]", with(func(s *network.Settings) { s.NTP = []string{"not a host"} })},
		{"allow-list host bits", "allowList[0]", with(func(s *network.Settings) { s.AllowList = []netip.Prefix{netip.MustParsePrefix("192.0.2.50/24")} })},
		{"bad time zone", "timeZone", with(func(s *network.Settings) { s.TimeZone = "Mars/Olympus" })},
		{"proxy with credentials", "httpsProxy", with(func(s *network.Settings) { s.HTTPSProxy = "http://user:pw@proxy.example.org:3128" })},
		{"proxy without scheme", "httpsProxy", with(func(s *network.Settings) { s.HTTPSProxy = "proxy.example.org:3128" })},
		{"no pod range", "cluster.pods", with(func(s *network.Settings) { s.Cluster.Pods = netip.Prefix{} })},
		{"pods overlap services", "cluster.services", with(func(s *network.Settings) { s.Cluster.Services = netip.PrefixFrom(network.DefaultPods.Addr(), 20) })},
		{"pods overlap the management network", "cluster.pods", with(func(s *network.Settings) {
			s.Cluster.Pods = netip.MustParsePrefix("198.51.100.0/24")
			staticV4("198.51.100.10/24", "")(s)
		})},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) { assertFieldErr(t, network.Validate(c.s), "NET_INVALID", c.field) })
	}
}
