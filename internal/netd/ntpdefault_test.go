// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/netd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/timesync"
)

// A box on a network that names no time server still gets the time: the
// image's default pool, until DHCP or the settings name servers, which
// replace it.
func TestTheDefaultPoolUntilDHCPOrTheSettingsNameServers(t *testing.T) {
	b := newBox(t)
	d := b.start()
	if servers, src := b.time.get(); !slices.Equal(servers, network.DefaultNTP) || src != timesync.SourceDefault {
		t.Fatalf("ntp %v from %v", servers, src)
	}
	b.workers.report4(t, "eth0", &netd.Lease4{
		Addr: netip.MustParsePrefix("192.0.2.100/24"), Router: netip.MustParseAddr("192.0.2.1"), Lease: time.Hour,
		DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")}, Search: []string{"sneakers.example.org"}, NTP: []string{"192.0.2.123"},
	})
	waitFor(t, func() bool { s, _ := b.time.get(); return slices.Equal(s, []string{"192.0.2.123"}) })
	// What DHCP gave is in Status, for the Network page.
	st := d.Status()
	if !slices.Equal(st.LearntDNS, []netip.Addr{netip.MustParseAddr("192.0.2.53")}) || !slices.Equal(st.LearntSearch, []string{"sneakers.example.org"}) || !slices.Equal(st.LearntNTP, []string{"192.0.2.123"}) || !slices.Equal(st.NTPServers, []string{"192.0.2.123"}) {
		t.Fatalf("learnt dns %v search %v ntp %v servers %v", st.LearntDNS, st.LearntSearch, st.LearntNTP, st.NTPServers)
	}
	s, _ := d.Get()
	s.NTP = []string{"time.example.org"}
	if _, err := d.Set(s); err != nil {
		t.Fatal(err)
	}
	if servers, src := b.time.get(); !slices.Equal(servers, []string{"time.example.org"}) || src != timesync.SourceSettings {
		t.Fatalf("ntp %v from %v", servers, src)
	}
}
