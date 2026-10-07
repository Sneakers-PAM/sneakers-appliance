// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package network_test

import (
	"net/netip"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

func TestRenderResolv(t *testing.T) {
	addrs := func(s ...string) []netip.Addr {
		var out []netip.Addr
		for _, a := range s {
			out = append(out, netip.MustParseAddr(a))
		}
		return out
	}
	got := string(network.RenderResolv(addrs("fe80::1", "192.0.2.53", "2001:db8::53", "192.0.2.54", "192.0.2.55"), []string{"a.example.org", "b.example.org", "c.example.org", "d.example.org", "e.example.org", "f.example.org", "g.example.org"}))
	want := "# Written by sneakers-netd.\nnameserver 192.0.2.53\nnameserver 2001:db8::53\nnameserver 192.0.2.54\nsearch a.example.org b.example.org c.example.org d.example.org e.example.org f.example.org\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if got := string(network.RenderResolv(nil, nil)); got != "# Written by sneakers-netd.\n" {
		t.Fatalf("empty: %q", got)
	}
}
