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

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netlink"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

const newAddr = "192.0.2.20/24"

// moved is static with the management IPv4 address moved, gateway and all.
func moved(nic string) network.Settings {
	s := static(nic)
	s.Management.IPv4.Address = netip.MustParsePrefix(newAddr)
	return s
}

func (b *box) saved() network.Settings {
	b.t.Helper()
	s, err := network.ReadFile(filepath.Join(b.state, "settings", "network.yaml"))
	if err != nil {
		b.t.Fatal(err)
	}
	return s
}

func (b *box) noUndoFile() {
	b.t.Helper()
	if _, err := os.Stat(filepath.Join(b.state, "settings", "network.prev.yaml")); !os.IsNotExist(err) {
		b.t.Fatalf("network.prev.yaml: %v", err)
	}
}

func (b *box) stage(s network.Settings) string {
	b.t.Helper()
	id, err := b.d.Stage(s)
	if err != nil {
		b.t.Fatal(err)
	}
	return id
}

// Staging changes nothing live and nothing on disk.
func TestStageChangesNothing(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	before := b.sys.prefixes("eth0")
	id := b.stage(moved("eth0"))
	if id == "" {
		t.Fatal("no id")
	}
	if got := b.sys.prefixes("eth0"); !slices.Equal(got, before) {
		t.Fatalf("addresses %v", got)
	}
	if b.saved().Management.IPv4.Address.String() != "192.0.2.10/24" {
		t.Fatal("network.yaml changed")
	}
	b.noUndoFile()
	cur, pending := d.Get()
	if cur.Management.IPv4.Address.String() != "192.0.2.10/24" || pending {
		t.Fatalf("%+v %v", cur.Management.IPv4, pending)
	}
	s, gotID, ok := d.Staged()
	if !ok || gotID != id || s.Management.IPv4.Address.String() != newAddr {
		t.Fatalf("staged %+v %q %v", s.Management.IPv4, gotID, ok)
	}
}

func TestStageRefusesInvalidSettings(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	bad := static("eth0")
	bad.Hostname = "not a name"
	if _, err := d.Stage(bad); !codes.Is(err, codes.NetInvalid) {
		t.Fatal(err)
	}
	bad = static("eth9")
	if _, err := d.Stage(bad); !codes.Is(err, codes.NetInvalid) {
		t.Fatal(err)
	}
	if _, _, ok := d.Staged(); ok {
		t.Fatal("staged")
	}
}

// A box that restarts with a stage waiting comes back on what it had.
func TestARestartDropsTheStage(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	b.start()
	b.stage(moved("eth0"))
	b.cancel()
	d := b.start()
	if _, _, ok := d.Staged(); ok {
		t.Fatal("the stage survived")
	}
	if got, _ := d.Get(); got.Management.IPv4.Address.String() != "192.0.2.10/24" {
		t.Fatalf("%+v", got.Management.IPv4)
	}
}

func TestDiscardDropsTheStage(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	id := b.stage(moved("eth0"))
	d.DiscardStaged()
	if _, _, ok := d.Staged(); ok {
		t.Fatal("still staged")
	}
	if _, err := d.Commit(context.Background(), id); !codes.Is(err, codes.NetInvalid) {
		t.Fatal(err)
	}
}

// A commit tests from the staged address with the old one still up, then
// applies, saves and keeps: no undo file, no timer.
func TestCommitTestsThenAppliesAndKeeps(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	var during []string
	b.sys.onReachFrom = func(netip.Addr) { during = b.sys.prefixes("eth0") }
	id := b.stage(moved("eth0"))
	tested, err := d.Commit(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tested, []string{"192.0.2.1"}) {
		t.Fatalf("tested %v", tested)
	}
	if !slices.Equal(b.sys.reachedFrom, []string{"192.0.2.1 from 192.0.2.20 on eth0"}) {
		t.Fatalf("reached %v", b.sys.reachedFrom)
	}
	if !slices.Contains(during, "192.0.2.10/24") || !slices.Contains(during, newAddr) {
		t.Fatalf("during the test %v", during)
	}
	if got := b.sys.prefixes("eth0"); slices.Contains(got, "192.0.2.10/24") || !slices.Contains(got, newAddr) {
		t.Fatalf("after %v", got)
	}
	if b.saved().Management.IPv4.Address.String() != newAddr {
		t.Fatal("not saved")
	}
	b.noUndoFile()
	if _, pending := d.Get(); pending {
		t.Fatal("pending")
	}
	if _, _, ok := d.Staged(); ok {
		t.Fatal("still staged")
	}
	b.clk.Advance(network.RevertAfter * 2)
	if got, _ := d.Get(); got.Management.IPv4.Address.String() != newAddr {
		t.Fatalf("reverted to %+v", got.Management.IPv4)
	}
}

// A gateway that doesn't answer refuses the commit: the test address goes,
// the live settings stay, and the stage stays so it can be fixed.
func TestCommitRefusedWhenTheGatewayDoesntAnswer(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	before := b.sys.prefixes("eth0")
	b.sys.reachErr = errDown
	id := b.stage(moved("eth0"))
	_, err := d.Commit(context.Background(), id)
	if !codes.Is(err, codes.NetGateway) {
		t.Fatal(err)
	}
	for _, want := range []string{"192.0.2.1", "192.0.2.20"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q lacks %s", err, want)
		}
	}
	if got := b.sys.prefixes("eth0"); !slices.Equal(got, before) {
		t.Fatalf("addresses %v, want %v", got, before)
	}
	if got, _ := d.Get(); got.Management.IPv4.Address.String() != "192.0.2.10/24" {
		t.Fatalf("%+v", got.Management.IPv4)
	}
	if b.saved().Management.IPv4.Address.String() != "192.0.2.10/24" {
		t.Fatal("saved")
	}
	if _, _, ok := d.Staged(); !ok {
		t.Fatal("the stage went")
	}
}

// The test address lasts seconds at most even if netd dies with it on the
// interface, it's never picked as a source, and sshd and osadmin, who
// rebind on Watch, never hear about it.
func TestTheTestAddressStaysOutOfSight(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	ch, stop := d.Watch()
	defer stop()
	<-ch
	var flagged []netlink.Addr
	var status []string
	b.sys.onReachFrom = func(netip.Addr) {
		b.sys.mu.Lock()
		flagged = slices.Clone(b.sys.addrs["eth0"])
		b.sys.mu.Unlock()
		b.sys.notices <- struct{}{}
		status = d.Status().Management
	}
	id := b.stage(moved("eth0"))
	b.sys.reachErr = errDown
	if _, err := d.Commit(context.Background(), id); err == nil {
		t.Fatal("no refusal")
	}
	if slices.Contains(status, newAddr) {
		t.Fatalf("Status showed it: %v", status)
	}
	i := slices.IndexFunc(flagged, func(a netlink.Addr) bool { return a.Prefix.String() == newAddr })
	if i < 0 || flagged[i].Valid == netlink.Forever || flagged[i].Valid > 60 || flagged[i].Preferred != 0 {
		t.Fatalf("%+v", flagged)
	}
	select {
	case a := <-ch:
		if slices.Contains(a.Management, newAddr) {
			t.Fatalf("Watch showed it: %v", a)
		}
	default:
	}
}

// A change that keeps the address only tests the new gateway: the live
// address is neither added nor removed.
func TestAGatewayChangeLeavesTheLiveAddressAlone(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	next := static("eth0")
	next.Management.IPv4.Gateway = netip.MustParseAddr("192.0.2.2")
	b.sys.reachErr = errDown
	if _, err := d.Commit(context.Background(), b.stage(next)); !codes.Is(err, codes.NetGateway) {
		t.Fatal(err)
	}
	if !slices.Contains(b.sys.prefixes("eth0"), "192.0.2.10/24") {
		t.Fatalf("the live address went: %v", b.sys.prefixes("eth0"))
	}
}

// IPv6 keys an address by its IP alone, so the same IP with another prefix
// would replace the live one: it's not added at all.
func TestTheSameIPv6AddressWithAnotherPrefixIsNotAdded(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	next := static("eth0")
	next.Management.IPv6.Address = netip.MustParsePrefix("2001:db8::10/56")
	if _, err := d.Commit(context.Background(), b.stage(next)); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(b.sys.reachedFrom, []string{"fe80::1 from 2001:db8::10 on eth0"}) {
		t.Fatalf("%v", b.sys.reachedFrom)
	}
	if got := b.sys.prefixes("eth0"); !slices.Contains(got, "2001:db8::10/56") || slices.Contains(got, "2001:db8::10/64") {
		t.Fatalf("%v", got)
	}
}

// IPv6 can't bind an address still in DAD: the test waits for it.
func TestTheTestWaitsForDAD(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	next := static("eth0")
	next.Management.IPv6.Address = netip.MustParsePrefix("2001:db8::20/64")
	b.sys.addrFlags = func(p netip.Prefix) uint32 {
		if p == next.Management.IPv6.Address {
			go func() {
				b.sys.mu.Lock()
				defer b.sys.mu.Unlock()
				for i, a := range b.sys.addrs["eth0"] {
					if a.Prefix == p {
						b.sys.addrs["eth0"][i].Flags &^= netlink.FlagTentative
					}
				}
			}()
			return netlink.FlagTentative
		}
		return 0
	}
	var flags uint32
	b.sys.onReachFrom = func(netip.Addr) {
		b.sys.mu.Lock()
		defer b.sys.mu.Unlock()
		for _, a := range b.sys.addrs["eth0"] {
			if a.Prefix == next.Management.IPv6.Address {
				flags = a.Flags
			}
		}
	}
	if _, err := d.Commit(context.Background(), b.stage(next)); err != nil {
		t.Fatal(err)
	}
	if flags&netlink.FlagTentative != 0 {
		t.Fatal("tested while tentative")
	}
}

// An address another host already holds fails DAD: refused, and removed.
func TestAnAddressThatFailsDADIsRefused(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	next := static("eth0")
	next.Management.IPv6.Address = netip.MustParsePrefix("2001:db8::20/64")
	b.sys.addrFlags = func(p netip.Prefix) uint32 {
		if p == next.Management.IPv6.Address {
			return netlink.FlagDADFailed
		}
		return 0
	}
	_, err := d.Commit(context.Background(), b.stage(next))
	if !codes.Is(err, codes.NetGateway) || !strings.Contains(err.Error(), "already") {
		t.Fatal(err)
	}
	if slices.Contains(b.sys.prefixes("eth0"), "2001:db8::20/64") {
		t.Fatal("left on the interface")
	}
}

// With IPv6 off the interface takes no IPv6 address, so it's on for the
// test and off again after, on failure too.
func TestIPv6IsTurnedOnOnlyForTheTest(t *testing.T) {
	b := newBox(t)
	cur := static("eth0")
	cur.Management.IPv6 = network.Family6{Mode: network.V6Off}
	b.writeSettings("network.yaml", cur)
	d := b.start()
	next := static("eth0")
	var mode network.Mode6
	b.sys.onReachFrom = func(netip.Addr) {
		b.sys.mu.Lock()
		defer b.sys.mu.Unlock()
		mode = b.sys.ipv6["eth0"]
	}
	b.sys.reachErr = errDown
	if _, err := d.Commit(context.Background(), b.stage(next)); !codes.Is(err, codes.NetGateway) {
		t.Fatal(err)
	}
	b.sys.mu.Lock()
	after := b.sys.ipv6["eth0"]
	b.sys.mu.Unlock()
	if mode == network.V6Off || after != network.V6Off {
		t.Fatalf("during %q after %q", mode, after)
	}
}

// A family the change leaves alone isn't tested: a gateway that was already
// dead doesn't hold up a DNS change.
func TestOnlyWhatChangedIsTested(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	next := static("eth0")
	next.DNS = []netip.Addr{netip.MustParseAddr("192.0.2.54")}
	b.sys.reachErr = errDown
	tested, err := d.Commit(context.Background(), b.stage(next))
	if err != nil || len(tested) != 0 || len(b.sys.reachedFrom) != 0 {
		t.Fatalf("%v %v %v", err, tested, b.sys.reachedFrom)
	}
	if got := b.saved().DNS; len(got) != 1 || got[0].String() != "192.0.2.54" {
		t.Fatalf("%v", got)
	}
}

// DHCP has no staged gateway to test, and neither does a static address
// with none.
func TestNothingToTestCommitsWithNoTest(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	next := static("eth0")
	next.Management.IPv4 = network.Family4{Mode: network.V4DHCP}
	b.sys.reachErr = errDown
	tested, err := d.Commit(context.Background(), b.stage(next))
	if err != nil || len(tested) != 0 || len(b.sys.reachedFrom) != 0 {
		t.Fatalf("%v %v %v", err, tested, b.sys.reachedFrom)
	}
	if b.saved().Management.IPv4.Mode != network.V4DHCP {
		t.Fatal("not saved")
	}
}

// A commit takes only the stage the admin looked at.
func TestCommitRefusesAnyOtherStage(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	if _, err := d.Commit(context.Background(), ""); !codes.Is(err, codes.NetInvalid) {
		t.Fatal(err)
	}
	old := b.stage(moved("eth0"))
	b.stage(moved("eth0"))
	_, err := d.Commit(context.Background(), old)
	if !codes.Is(err, codes.NetInvalid) || network.Field(err) != "staged" {
		t.Fatal(err)
	}
	if b.saved().Management.IPv4.Address.String() != "192.0.2.10/24" {
		t.Fatal("applied")
	}
}

// The staged settings are a whole set: committing them after the live ones
// moved on would undo that change, so it's refused.
func TestCommitRefusesAStageTheLiveSettingsMovedPast(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	id := b.stage(moved("eth0"))
	other := static("eth0")
	other.TimeZone = "America/New_York"
	if _, err := d.Set(other); err != nil {
		t.Fatal(err)
	}
	_, err := d.Commit(context.Background(), id)
	if !codes.Is(err, codes.NetInvalid) || network.Field(err) != "staged" {
		t.Fatal(err)
	}
	if got, _ := d.Get(); got.TimeZone != "America/New_York" {
		t.Fatalf("%+v", got)
	}
}

// The allow-list reset still has its window: Set without keep is unchanged.
func TestSetWithoutKeepStillHasItsWindow(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	next := static("eth0")
	next.AllowList = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	tok, err := d.Set(next)
	if err != nil || tok == "" {
		t.Fatalf("%q %v", tok, err)
	}
	b.clk.Advance(network.RevertAfter)
	waitFor(t, func() bool { _, pending := d.Get(); return !pending })
	if got, _ := d.Get(); len(got.AllowList) != 0 {
		t.Fatalf("not reverted: %+v", got.AllowList)
	}
}

func TestCommitWaitsForAPendingChange(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	id := b.stage(moved("eth0"))
	next := static("eth0")
	next.AllowList = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if _, err := d.Set(next); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Commit(context.Background(), id); !codes.Is(err, codes.NetInvalid) {
		t.Fatal(err)
	}
}

// The console's path: the change was shown and confirmed, so it's kept at
// once, even one that moves the address.
func TestSetAndKeepHasNoWindow(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	if err := d.SetAndKeep(moved("eth0")); err != nil {
		t.Fatal(err)
	}
	b.noUndoFile()
	if _, pending := d.Get(); pending {
		t.Fatal("pending")
	}
	if b.saved().Management.IPv4.Address.String() != newAddr {
		t.Fatal("not saved")
	}
	b.clk.Advance(network.RevertAfter * 2)
	if got, _ := d.Get(); got.Management.IPv4.Address.String() != newAddr {
		t.Fatalf("reverted to %+v", got.Management.IPv4)
	}
	if len(b.sys.reachedFrom) != 0 {
		t.Fatalf("the console's change was tested first: %v", b.sys.reachedFrom)
	}
}
