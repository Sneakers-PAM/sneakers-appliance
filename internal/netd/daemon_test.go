// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd_test

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netlink"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/timesync"
)

// A box that was never set up runs the first-boot screen's defaults on
// its first NIC with a link: DHCP for IPv4, SLAAC (with RA) for IPv6.
func TestFirstStartRunsTheDefaultsOnTheFirstLinkedNIC(t *testing.T) {
	down := netd.Link{Name: "eth0", Up: false, Bus: eth0.Bus}
	b := newBox(t, down, eth1)
	d := b.start()
	s, pending := d.Get()
	if s.Management.Name != "eth1" || s.Management.IPv4.Mode != network.V4DHCP || s.Management.IPv6.Mode != network.V6SLAAC || pending {
		t.Fatalf("settings %+v pending %v", s.Management, pending)
	}
	waitFor(t, func() bool { return slices.Equal(b.workers.running(t), []string{"dhcpv4 eth1", "ra eth1"}) })
	if b.sys.ipv6["eth1"] != network.V6SLAAC {
		t.Fatalf("ipv6 mode %v", b.sys.ipv6)
	}
	if !slices.Contains(b.sys.up, "lo") || !slices.Contains(b.sys.up, "eth1") {
		t.Fatalf("links up %v", b.sys.up)
	}
	if _, err := os.Stat(filepath.Join(b.state, "settings", "network.yaml")); !os.IsNotExist(err) {
		t.Fatalf("the defaults were written before anyone set them: %v", err)
	}
}

func TestStaticSettingsAreApplied(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	b.sys.kernelAddr("eth0", "192.0.2.99/24", netlink.FlagPermanent)
	b.start()
	if got := b.sys.prefixes("eth0"); !slices.Equal(got, []string{"192.0.2.10/24", "2001:db8::10/64"}) {
		t.Fatalf("addresses %v", got)
	}
	routes, _ := b.sys.Routes("eth0")
	var gws []string
	for _, r := range routes {
		gws = append(gws, r.Gateway.String())
	}
	slices.Sort(gws)
	if !slices.Equal(gws, []string{"192.0.2.1", "fe80::1"}) {
		t.Fatalf("default routes %v", gws)
	}
	if got := b.read("resolv.conf"); got != "# Written by sneakers-netd.\nnameserver 192.0.2.53\nnameserver 2001:db8::53\nsearch sneakers.example.org\n" {
		t.Fatalf("resolv.conf:\n%s", got)
	}
	if b.sys.hostname != "appliance.sneakers.example.org" {
		t.Fatalf("hostname %q", b.sys.hostname)
	}
	if servers, src := b.time.get(); !slices.Equal(servers, []string{"192.0.2.123", "time.example.org"}) || src != timesync.SourceSettings {
		t.Fatalf("ntp %v from %v", servers, src)
	}
	if len(b.workers.running(t)) != 0 {
		t.Fatalf("workers %v in static mode", b.workers.running(t))
	}
}

func TestDHCPLeaseFeedsTheAddressResolverNTPAndHostname(t *testing.T) {
	b := newBox(t)
	b.start()
	b.workers.report4(t, "eth0", &netd.Lease4{
		Addr: netip.MustParsePrefix("192.0.2.100/24"), Router: netip.MustParseAddr("192.0.2.1"), Lease: time.Hour,
		DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")}, NTP: []string{"192.0.2.123"},
		Hostname: "box1", Domain: "sneakers.example.org",
	})
	waitFor(t, func() bool { return slices.Contains(b.sys.prefixes("eth0"), "192.0.2.100/24") })
	addrs, _ := b.sys.Addrs("eth0")
	if addrs[0].Valid != 3600 {
		t.Fatalf("lease lifetime %d", addrs[0].Valid)
	}
	waitFor(t, func() bool { return strings.Contains(b.read("resolv.conf"), "nameserver 192.0.2.53") })
	if got := b.read("resolv.conf"); !strings.Contains(got, "search sneakers.example.org") {
		t.Fatalf("resolv.conf:\n%s", got)
	}
	waitFor(t, func() bool { s, _ := b.time.get(); return slices.Equal(s, []string{"192.0.2.123"}) })
	if _, src := b.time.get(); src != timesync.SourceDHCP {
		t.Fatalf("source %v", src)
	}
	waitFor(t, func() bool {
		b.sys.mu.Lock()
		defer b.sys.mu.Unlock()
		return b.sys.hostname == "box1.sneakers.example.org"
	})
	b.workers.report4(t, "eth0", nil)
	waitFor(t, func() bool { return !slices.Contains(b.sys.prefixes("eth0"), "192.0.2.100/24") })
}

func (f *fakeSys) host() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hostname
}

// The kernel host name: the setting, else the DHCP name, else the box's
// own name. Only the first two are the box's host name for certificates.
func TestTheKernelHostNameFallsBackToTheBoxName(t *testing.T) {
	b := newBox(t)
	b.fallback = "sneakers-0a1b2c3d"
	b.start()
	waitFor(t, func() bool { return b.sys.host() == "sneakers-0a1b2c3d" })
	addrs, stop := b.d.Watch()
	defer stop()
	if a := <-addrs; a.Hostname != "" {
		t.Fatalf("the box's own name was reported as its host name: %q", a.Hostname)
	}
	b.workers.report4(t, "eth0", &netd.Lease4{
		Addr: netip.MustParsePrefix("192.0.2.100/24"), Router: netip.MustParseAddr("192.0.2.1"), Lease: time.Hour,
		Hostname: "box1", Domain: "sneakers.example.org",
	})
	waitFor(t, func() bool { return b.sys.host() == "box1.sneakers.example.org" })
	b.workers.report4(t, "eth0", nil)
	waitFor(t, func() bool { return b.sys.host() == "sneakers-0a1b2c3d" })
}

func TestTheSettingWinsOverTheBoxName(t *testing.T) {
	b := newBox(t)
	b.fallback = "sneakers-0a1b2c3d"
	b.writeSettings("network.yaml", static("eth0"))
	b.start()
	if got := b.sys.host(); got != "appliance.sneakers.example.org" {
		t.Fatalf("hostname %q", got)
	}
}

func TestRouterAdvertisementDNSServersReachTheResolver(t *testing.T) {
	b := newBox(t)
	s := network.Defaults("eth0")
	s.Management.IPv4.Mode = network.V4Off
	b.writeSettings("network.yaml", s)
	b.sys.kernelAddr("eth0", "192.0.2.99/24", netlink.FlagPermanent)
	b.start()
	if got := b.sys.prefixes("eth0"); len(got) != 0 {
		t.Fatalf("IPv4 off left %v", got)
	}
	waitFor(t, func() bool { return slices.Equal(b.workers.running(t), []string{"ra eth0"}) })
	b.workers.reportRA(t, "eth0", &netd.RAInfo{RDNSS: []netip.Addr{netip.MustParseAddr("2001:db8::53")}, Search: []string{"sneakers.example.org"}})
	waitFor(t, func() bool { return strings.Contains(b.read("resolv.conf"), "nameserver 2001:db8::53") })
	// RA's O flag asks for the stateless DHCPv6 information (NTP).
	b.workers.reportRA(t, "eth0", &netd.RAInfo{Other: true, RDNSS: []netip.Addr{netip.MustParseAddr("2001:db8::53")}})
	waitFor(t, func() bool { return slices.Contains(b.workers.running(t), "dhcpv6-info eth0") })
	b.workers.report6(t, "eth0", &netd.Lease6{NTP: []string{"2001:db8::123"}})
	waitFor(t, func() bool { s, _ := b.time.get(); return slices.Equal(s, []string{"2001:db8::123"}) })
}

func TestStatefulDHCPv6AddsItsAddress(t *testing.T) {
	b := newBox(t)
	s := network.Defaults("eth0")
	s.Management.IPv4.Mode = network.V4Off
	s.Management.IPv6.Mode = network.V6DHCPv6
	b.writeSettings("network.yaml", s)
	b.start()
	waitFor(t, func() bool { return slices.Equal(b.workers.running(t), []string{"dhcpv6 eth0", "ra eth0"}) })
	if b.sys.ipv6["eth0"] != network.V6DHCPv6 {
		t.Fatalf("ipv6 mode %v", b.sys.ipv6)
	}
	b.workers.report6(t, "eth0", &netd.Lease6{Addr: netip.MustParsePrefix("2001:db8:1::100/128"), Valid: 2 * time.Hour, Preferred: time.Hour,
		DNS: []netip.Addr{netip.MustParseAddr("2001:db8:1::53")}})
	waitFor(t, func() bool { return slices.Contains(b.sys.prefixes("eth0"), "2001:db8:1::100/128") })
	waitFor(t, func() bool { return strings.Contains(b.read("resolv.conf"), "nameserver 2001:db8:1::53") })
}

// In SLAAC mode the kernel's own addresses stay; leaving SLAAC removes
// them.
func TestSLAACAddressesAreTheKernels(t *testing.T) {
	b := newBox(t)
	s := network.Defaults("eth0")
	b.writeSettings("network.yaml", s)
	d := b.start()
	b.sys.kernelAddr("eth0", "2001:db8::5054:ff:fe00:1/64", 0)
	b.sys.kernelAddr("eth0", "fe80::5054:ff:fe00:1/64", netlink.FlagPermanent)
	next := s
	next.Management.IPv6 = network.Family6{Mode: network.V6Static, Address: netip.MustParsePrefix("2001:db8::10/64")}
	if _, err := d.Set(next); err != nil {
		t.Fatal(err)
	}
	if got := b.sys.prefixes("eth0"); !slices.Equal(got, []string{"2001:db8::10/64", "fe80::5054:ff:fe00:1/64"}) {
		t.Fatalf("addresses %v", got)
	}
}

// A change to the DNS servers alone leaves the address clients running,
// so a renewing lease isn't dropped under an admin's session.
func TestAnUnchangedInterfaceIsLeftAlone(t *testing.T) {
	b := newBox(t)
	d := b.start()
	b.workers.report4(t, "eth0", &netd.Lease4{Addr: netip.MustParsePrefix("192.0.2.100/24"), Lease: time.Hour})
	waitFor(t, func() bool { return slices.Contains(b.sys.prefixes("eth0"), "192.0.2.100/24") })
	// The default settings run DHCPv4 and the RA client; both must have
	// started before they're counted.
	b.workers.waitStarted(t, "dhcpv4 eth0", "ra eth0")
	b.workers.mu.Lock()
	before := len(b.workers.started)
	ctxs := map[string]context.Context{"dhcpv4 eth0": b.workers.live["dhcpv4 eth0"], "ra eth0": b.workers.live["ra eth0"]}
	b.workers.mu.Unlock()
	s, _ := d.Get()
	s.DNS = []netip.Addr{netip.MustParseAddr("192.0.2.54")}
	if _, err := d.Set(s); err != nil {
		t.Fatal(err)
	}
	b.workers.mu.Lock()
	after := len(b.workers.started)
	b.workers.mu.Unlock()
	if after != before || !slices.Contains(b.sys.prefixes("eth0"), "192.0.2.100/24") {
		t.Fatalf("workers restarted (%d to %d) or the lease dropped: %v", before, after, b.sys.prefixes("eth0"))
	}
	for name, ctx := range ctxs {
		if ctx.Err() != nil {
			t.Fatalf("%s was stopped", name)
		}
	}
	if !strings.Contains(b.read("resolv.conf"), "nameserver 192.0.2.54") {
		t.Fatalf("resolv.conf:\n%s", b.read("resolv.conf"))
	}
}

func TestSetKeepsThePreviousSettingsUntilConfirmed(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	next := static("eth0")
	next.Management.IPv4.Address = netip.MustParsePrefix("192.0.2.20/24")
	tok, err := d.Set(next)
	if err != nil {
		t.Fatal(err)
	}
	prev := filepath.Join(b.state, "settings", "network.prev.yaml")
	if _, err := os.Stat(prev); err != nil {
		t.Fatalf("no network.prev.yaml during the window: %v", err)
	}
	if _, pending := d.Get(); !pending {
		t.Fatal("not pending")
	}
	if err := d.Confirm(tok); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(prev); !os.IsNotExist(err) {
		t.Fatalf("network.prev.yaml after Confirm: %v", err)
	}
	got, err := network.ReadFile(filepath.Join(b.state, "settings", "network.yaml"))
	if err != nil || got.Management.IPv4.Address.String() != "192.0.2.20/24" {
		t.Fatalf("network.yaml %+v %v", got.Management.IPv4, err)
	}
}

func TestAnUnconfirmedChangeIsUndone(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	next := static("eth0")
	next.Management.IPv4.Address = netip.MustParsePrefix("192.0.2.20/24")
	if _, err := d.Set(next); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(b.sys.prefixes("eth0"), "192.0.2.20/24") {
		t.Fatalf("addresses %v", b.sys.prefixes("eth0"))
	}
	b.clk.Advance(121 * time.Second)
	if got := b.sys.prefixes("eth0"); !slices.Contains(got, "192.0.2.10/24") || slices.Contains(got, "192.0.2.20/24") {
		t.Fatalf("after the revert: %v", got)
	}
	got, _ := network.ReadFile(filepath.Join(b.state, "settings", "network.yaml"))
	if got.Management.IPv4.Address.String() != "192.0.2.10/24" {
		t.Fatalf("network.yaml after the revert: %v", got.Management.IPv4.Address)
	}
	if _, err := os.Stat(filepath.Join(b.state, "settings", "network.prev.yaml")); !os.IsNotExist(err) {
		t.Fatalf("network.prev.yaml after the revert: %v", err)
	}
}

// netd stopped (or the box lost power) inside the window: the next start
// undoes the change nobody confirmed.
func TestARestartInsideTheWindowUndoesTheChange(t *testing.T) {
	b := newBox(t)
	next := static("eth0")
	next.Management.IPv4.Address = netip.MustParsePrefix("192.0.2.20/24")
	b.writeSettings("network.yaml", next)
	b.writeSettings("network.prev.yaml", static("eth0"))
	d := b.start()
	if s, _ := d.Get(); s.Management.IPv4.Address.String() != "192.0.2.10/24" {
		t.Fatalf("settings %v", s.Management.IPv4.Address)
	}
	if !slices.Contains(b.sys.prefixes("eth0"), "192.0.2.10/24") {
		t.Fatalf("addresses %v", b.sys.prefixes("eth0"))
	}
}

func TestSetRefusesInvalidSettings(t *testing.T) {
	b := newBox(t)
	d := b.start()
	s, _ := d.Get()
	s.DNS = []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.4")}
	_, err := d.Set(s)
	if !codes.Is(err, codes.NetInvalid) || network.Field(err) != "dns" {
		t.Fatalf("err %v", err)
	}
	s, _ = d.Get()
	s.Management.Name = "eth9"
	if _, err := d.Set(s); !codes.Is(err, codes.NetInvalid) || network.Field(err) != "management.name" {
		t.Fatalf("an unknown NIC: %v", err)
	}
}

// 22 and 8443 stay closed until first boot opens them; the choice
// survives a netd restart, and a finished setup opens both.
func TestTheManagementPortsFollowTheSetupSteps(t *testing.T) {
	b := newBox(t)
	s := static("eth0")
	s.AllowList = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/64")}
	b.writeSettings("network.yaml", s)
	d := b.start()
	if tb := b.sys.lastTable(); tb.Open22 || tb.Open8443 || tb.MgmtIf != "eth0" {
		t.Fatalf("first table %+v", tb)
	}
	if err := d.SetManagementPorts(true, false); err != nil {
		t.Fatal(err)
	}
	tb := b.sys.lastTable()
	if !tb.Open22 || tb.Open8443 || len(tb.AllowV4) != 1 || tb.AllowV4[0].String() != "192.0.2.0/24" || len(tb.AllowV6) != 1 {
		t.Fatalf("table %+v", tb)
	}
	if st := d.Status(); !st.SSHOpen || st.HTTPSOpen {
		t.Fatalf("status %+v", st)
	}
	b.cancel()
	b.sys.tables = nil
	b.start()
	if tb := b.sys.lastTable(); !tb.Open22 || tb.Open8443 {
		t.Fatalf("after a restart %+v", tb)
	}
	b.cancel()
	if err := os.MkdirAll(filepath.Join(b.state, "setup"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.state, "setup", "done"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	b.start()
	if tb := b.sys.lastTable(); !tb.Open22 || !tb.Open8443 {
		t.Fatalf("after setup %+v", tb)
	}
}

func TestServicePortsGoOnTheServiceInterface(t *testing.T) {
	b := newBox(t, eth0, eth1)
	s := static("eth0")
	s.Service = &network.Interface{Name: "eth1", IPv4: network.Family4{Mode: network.V4DHCP}, IPv6: network.Family6{Mode: network.V6Off}}
	b.writeSettings("network.yaml", s)
	d := b.start()
	if err := d.SetServicePorts([]netd.PortRule{{Protocol: "tcp", Port: 443}}); err != nil {
		t.Fatal(err)
	}
	tb := b.sys.lastTable()
	if tb.Service == nil || tb.Service.Iface != "eth1" || len(tb.Service.Rules) != 1 || tb.Service.Rules[0].Port != 443 {
		t.Fatalf("table %+v", tb)
	}
	if err := d.SetServicePorts([]netd.PortRule{{Protocol: "icmp", Port: 1}}); !codes.Is(err, codes.NetInvalid) {
		t.Fatalf("a bad protocol: %v", err)
	}
	waitFor(t, func() bool { return slices.Contains(b.workers.running(t), "dhcpv4 eth1") })
}

func TestWatchSendsTheAddressesOnEveryChange(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	ch, stop := d.Watch()
	defer stop()
	first := next(t, ch)
	if !slices.Equal(first.Management, []string{"192.0.2.10/24", "2001:db8::10/64"}) || first.Hostname != "appliance.sneakers.example.org" {
		t.Fatalf("first %+v", first)
	}
	// A tentative address isn't usable yet, and a link-local one is never
	// a management address.
	b.sys.kernelAddr("eth0", "2001:db8::77/64", netlink.FlagTentative)
	b.sys.kernelAddr("eth0", "fe80::1/64", netlink.FlagPermanent)
	select {
	case ev := <-ch:
		t.Fatalf("an event for no usable change: %+v", ev)
	case <-time.After(300 * time.Millisecond):
	}
	b.sys.mu.Lock()
	for i := range b.sys.addrs["eth0"] {
		b.sys.addrs["eth0"][i].Flags &^= netlink.FlagTentative
	}
	b.sys.mu.Unlock()
	b.sys.notices <- struct{}{}
	ev := next(t, ch)
	if !slices.Contains(ev.Management, "2001:db8::77/64") {
		t.Fatalf("after DAD %+v", ev)
	}
	if st := d.Status(); !slices.Contains(st.Management, "2001:db8::77/64") {
		t.Fatalf("status %+v", st)
	}
}

func next(t *testing.T, ch <-chan netd.Addresses) netd.Addresses {
	t.Helper()
	select {
	case a := <-ch:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("no address event")
	}
	return netd.Addresses{}
}

func TestInterfacesLeaveOutLoopback(t *testing.T) {
	b := newBox(t, netd.Link{Name: "lo", Up: true}, eth0, eth1)
	d := b.start()
	got, err := d.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "eth0" || got[0].MAC == "" || got[0].Driver != "virtio_net" {
		t.Fatalf("interfaces %+v", got)
	}
}

func checkByName(cs []netd.Check, name string) []netd.Check {
	var out []netd.Check
	for _, c := range cs {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

func TestChecksAllPass(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	cs := d.Checks(context.Background())
	for _, c := range cs {
		if c.State != netd.CheckOK {
			t.Errorf("%s: %s %s %s", c.Name, c.State, c.Code, c.Detail)
		}
	}
	if len(checkByName(cs, "dns")) != 2 || len(checkByName(cs, "gateway")) != 2 {
		t.Fatalf("checks %+v", cs)
	}
	// Each DNS server is asked for the first NTP name.
	if !slices.Contains(b.sys.dnsAsked, "192.0.2.53 time.example.org") {
		t.Fatalf("dns asked %v", b.sys.dnsAsked)
	}
	if ntp := checkByName(cs, "ntp")[0]; !strings.Contains(ntp.Detail, "12ms") {
		t.Fatalf("ntp %+v", ntp)
	}
}

func TestChecksWithoutAnAddressBlockSetup(t *testing.T) {
	b := newBox(t)
	b.start()
	cs := d0(b).Checks(context.Background())
	addr := checkByName(cs, "address")
	if len(addr) != 1 || addr[0].State != netd.CheckFailed || addr[0].Code != "NET_NO_ADDRESS" || addr[0].Skippable {
		t.Fatalf("address %+v", addr)
	}
}

func d0(b *box) *netd.Daemon { return b.d }

func TestChecksReportEachProblem(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	b.sys.reachErr = errDown
	b.sys.dnsErr[netip.MustParseAddr("2001:db8::53")] = errDown
	b.time.status.State = timesync.StateUnsynced
	b.time.status.LastError = "no server answered"
	d := b.start()
	cs := d.Checks(context.Background())
	for _, c := range checkByName(cs, "gateway") {
		if c.State != netd.CheckFailed || c.Code != "NET_GATEWAY" || !c.Skippable {
			t.Fatalf("gateway %+v", c)
		}
	}
	dns := checkByName(cs, "dns")
	if dns[0].State != netd.CheckOK || dns[1].State != netd.CheckFailed || dns[1].Code != "NET_DNS" || !strings.Contains(dns[1].Detail, "2001:db8::53") {
		t.Fatalf("dns %+v", dns)
	}
	if ntp := checkByName(cs, "ntp")[0]; ntp.State != netd.CheckFailed || ntp.Code != "NET_NTP" || !ntp.Skippable {
		t.Fatalf("ntp %+v", ntp)
	}
}

// A DHCP family that never got a lease is a warning when another family
// gave the management interface an address.
func TestChecksWarnForAFamilyWithoutAnAddress(t *testing.T) {
	b := newBox(t)
	s := static("eth0")
	s.Management.IPv4 = network.Family4{Mode: network.V4DHCP}
	b.writeSettings("network.yaml", s)
	d := b.start()
	addr := checkByName(d.Checks(context.Background()), "address")
	var v4 *netd.Check
	for i := range addr {
		if strings.Contains(addr[i].Detail, "IPv4") {
			v4 = &addr[i]
		}
	}
	if v4 == nil || v4.State != netd.CheckWarn || v4.Code != "NET_DHCP_TIMEOUT" || !v4.Skippable {
		t.Fatalf("address %+v", addr)
	}
}
