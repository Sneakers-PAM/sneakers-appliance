// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package network_test

import (
	"net/netip"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestExposed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		addrs []netip.Addr
		allow []netip.Prefix
		want  bool
	}{
		{"public v4 and any", addrs("198.51.100.7"), prefixes("0.0.0.0/0"), true},
		{"public v4 and a /7", addrs("198.51.100.7"), prefixes("192.0.0.0/7"), true},
		{"public v4 and a /8", addrs("198.51.100.7"), prefixes("198.0.0.0/8"), false},
		{"public v6 and any", addrs("2001:db8::7"), prefixes("::/0"), true},
		{"public v6 and a /31", addrs("2001:db8::7"), prefixes("2001:db8::/31"), true},
		{"public v6 and a /32", addrs("2001:db8::7"), prefixes("2001:db8::/32"), false},
		{"private v4 only", addrs("10.1.2.3"), prefixes("0.0.0.0/0"), false},     // scrub:allow=private-ip
		{"shared space only", addrs("100.64.1.2"), prefixes("0.0.0.0/0"), false}, // RFC 6598
		{"ula only", addrs("fd00::5"), prefixes("::/0"), false},                  // scrub:allow=private-ip
		{"link-local only", addrs("fe80::1"), prefixes("::/0"), false},
		{"empty allow-list is any source", addrs("198.51.100.7"), nil, true},
		{"private plus public", addrs("10.9.8.7", "198.51.100.7"), prefixes("10.0.0.0/8", "0.0.0.0/0"), true}, // scrub:allow=private-ip
	} {
		if got := network.Exposed(tc.addrs, tc.allow); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}
