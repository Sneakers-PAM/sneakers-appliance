// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package network

import "net/netip"

var sharedSpace = netip.MustParsePrefix("100.64.0.0/10")

// Exposed reports the exposure warning of spec 2 Section 2.9: a management
// address is a global unicast address outside RFC 1918, RFC 6598 and the
// IPv6 ULA range, and the allow-list is wide open (empty, which means any
// source during setup, or a prefix shorter than /8 for IPv4 or /32 for
// IPv6).
func Exposed(mgmt []netip.Addr, allow []netip.Prefix) bool {
	public4, public6 := false, false
	for _, a := range mgmt {
		a = a.Unmap()
		if !a.IsGlobalUnicast() || a.IsPrivate() || sharedSpace.Contains(a) {
			continue
		}
		if a.Is4() {
			public4 = true
		} else {
			public6 = true
		}
	}
	if !public4 && !public6 {
		return false
	}
	if len(allow) == 0 {
		return true
	}
	for _, p := range allow {
		if p.Addr().Is4() && public4 && p.Bits() < 8 {
			return true
		}
		if p.Addr().Is6() && public6 && p.Bits() < 32 {
			return true
		}
	}
	return false
}
