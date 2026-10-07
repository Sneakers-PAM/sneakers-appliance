// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wizard

import (
	"net/netip"
)

// hostsOf turns management addresses into URL hosts, leaving out
// link-local ones and bracketing IPv6.
func hostsOf(addrs []string) []string {
	var out []string
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			p, perr := netip.ParsePrefix(a)
			if perr != nil {
				continue
			}
			ip = p.Addr()
		}
		if ip.IsLinkLocalUnicast() {
			continue
		}
		if ip.Is6() {
			out = append(out, "["+ip.String()+"]")
			continue
		}
		out = append(out, ip.String())
	}
	return out
}
