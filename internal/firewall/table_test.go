// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package firewall_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/firewall"
)

func prefixes(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range s {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

func lines(rs []firewall.Rule) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.String())
	}
	return out
}

func assertRules(t *testing.T, got []firewall.Rule, want ...string) {
	t.Helper()
	if g := lines(got); !slices.Equal(g, want) {
		t.Fatalf("rules:\n%s\nwant:\n%s", strings.Join(g, "\n"), strings.Join(want, "\n"))
	}
}

// Before the first-boot step that opens them, 22 and 8443 have no accept
// rule at all: only the drops.
func TestClosedPortsHaveNoAcceptRule(t *testing.T) {
	p := firewall.Plan(firewall.Table{MgmtIf: "eth0"})
	assertRules(t, p.Rules,
		"ct state established,related accept",
		"tcp dport 22 drop",
		"tcp dport 8443 drop",
	)
}

// During setup the allow-list is empty: any source, but only on the
// management interface.
func TestOpenWithoutAllowListAcceptsAnySourceOnTheManagementInterface(t *testing.T) {
	p := firewall.Plan(firewall.Table{MgmtIf: "eth0", Open22: true})
	assertRules(t, p.Rules,
		"ct state established,related accept",
		`iifname "eth0" tcp dport 22 accept`,
		"tcp dport 22 drop",
		"tcp dport 8443 drop",
	)
}

func TestAllowListBothFamilies(t *testing.T) {
	p := firewall.Plan(firewall.Table{MgmtIf: "eth0", Open22: true, Open8443: true,
		AllowV4: prefixes("192.0.2.0/24"), AllowV6: prefixes("2001:db8::/64")})
	assertRules(t, p.Rules,
		"ct state established,related accept",
		`iifname "eth0" ip saddr @allow4 tcp dport 22 accept`,
		`iifname "eth0" ip6 saddr @allow6 tcp dport 22 accept`,
		`iifname "eth0" ip saddr @allow4 tcp dport 8443 accept`,
		`iifname "eth0" ip6 saddr @allow6 tcp dport 8443 accept`,
		"tcp dport 22 drop",
		"tcp dport 8443 drop",
	)
	if len(p.Sets) != 2 || p.Sets[0].Name != "allow4" || p.Sets[1].Name != "allow6" {
		t.Fatalf("sets %+v", p.Sets)
	}
}

// An allow-list of one family leaves the other family no way in.
func TestAllowListOfOneFamilyShutsTheOther(t *testing.T) {
	p := firewall.Plan(firewall.Table{MgmtIf: "eth0", Open22: true, AllowV4: prefixes("192.0.2.50/32")})
	assertRules(t, p.Rules,
		"ct state established,related accept",
		`iifname "eth0" ip saddr @allow4 tcp dport 22 accept`,
		"tcp dport 22 drop",
		"tcp dport 8443 drop",
	)
}

func TestServicePortsAreCarried(t *testing.T) {
	p := firewall.Plan(firewall.Table{MgmtIf: "eth0", Service: &firewall.ServicePorts{Iface: "eth1", Rules: []firewall.PortRule{
		{Protocol: "tcp", Port: 443},
		{Protocol: "udp", Port: 51820, AllowV4: prefixes("198.51.100.0/24")},
	}}})
	assertRules(t, p.Rules,
		"ct state established,related accept",
		`iifname "eth1" tcp dport 443 accept`,
		`iifname "eth1" ip saddr @svc2v4 udp dport 51820 accept`,
		"tcp dport 22 drop",
		"tcp dport 8443 drop",
	)
}

// Interval sets refuse overlapping elements, so the allow-list is merged
// into disjoint ranges first.
func TestIntervalsAreMerged(t *testing.T) {
	got := firewall.Intervals(prefixes("192.0.2.0/25", "192.0.2.128/25", "192.0.2.7/32", "198.51.100.0/24"))
	want := []string{"192.0.2.0-192.0.2.255", "198.51.100.0-198.51.100.255"}
	var g []string
	for _, r := range got {
		g = append(g, r.String())
	}
	if !slices.Equal(g, want) {
		t.Fatalf("intervals %v, want %v", g, want)
	}
}

func TestIntervalsCoverTheWholeSpace(t *testing.T) {
	got := firewall.Intervals(prefixes("::/0"))
	if len(got) != 1 || got[0].String() != "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" {
		t.Fatalf("intervals %v", got)
	}
}
