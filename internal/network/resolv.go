// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"net/netip"
	"strings"
)

// The resolver's own limits (resolv.conf(5)).
const (
	resolvMaxServers = 3
	resolvMaxSearch  = 6
)

// RenderResolv is /run/sneakers/resolv.conf for the given servers and
// search list. Link-local servers are left out: resolv.conf can't carry
// their zone. The resolver reads at most three servers and six domains.
func RenderResolv(dns []netip.Addr, search []string) []byte {
	var b strings.Builder
	b.WriteString("# Written by sneakers-netd.\n")
	n := 0
	for _, a := range dns {
		if n == resolvMaxServers {
			break
		}
		if !a.IsValid() || a.IsLinkLocalUnicast() {
			continue
		}
		b.WriteString("nameserver " + a.Unmap().String() + "\n")
		n++
	}
	if len(search) > resolvMaxSearch {
		search = search[:resolvMaxSearch]
	}
	if len(search) > 0 {
		b.WriteString("search " + strings.Join(search, " ") + "\n")
	}
	return []byte(b.String())
}
