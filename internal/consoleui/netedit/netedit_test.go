// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netedit

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/consoletest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui/tuitest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

func chrome() consoleui.Chrome {
	return consoleui.Chrome{Version: "0.1.0", Now: func() time.Time { return time.Date(2026, 10, 7, 14, 3, 0, 0, time.UTC) }}
}

var nics = []sources.NIC{{Name: "ens192", MAC: "00:50:56:00:00:01", Link: true}, {Name: "ens224", MAC: "00:50:56:00:00:02"}}

func TestEditorScreens(t *testing.T) {
	f := form{nics: nics, port: "ens192"}
	tuitest.Golden(t, "field-port", FieldPage(chrome(), f, fieldPort, 1, 4, ""))
	tuitest.Golden(t, "field-address", FieldPage(chrome(), f, fieldAddress, 2, 4, ""))
	tuitest.Golden(t, "field-address-error", FieldPage(chrome(), f, fieldAddress, 2, 4, `"192.0.2.10" isn't an address with its prefix, such as 192.0.2.10/24`))
	f.address = netip.MustParsePrefix("192.0.2.10/24")
	tuitest.Golden(t, "field-gateway", FieldPage(chrome(), f, fieldGateway, 3, 4, ""))
	tuitest.Golden(t, "checks-running", ChecksPage(chrome(), []sources.Check{{Name: "link", State: sources.CheckOK}, {Name: "gateway", State: sources.CheckRunning}}, "", false))
	tuitest.Golden(t, "checks-done", ChecksPage(chrome(), []sources.Check{
		{Name: "cable on ens192", State: sources.CheckOK}, {Name: "address 192.0.2.10/24", State: sources.CheckOK},
		{Name: "gateway 192.0.2.1", State: sources.CheckOK}, {Name: "time server", State: sources.CheckWarn, Detail: "no answer; certificate checks can fail if the clock drifts"},
	}, "", true))
	tuitest.Golden(t, "checks-starting", ChecksPage(chrome(), nil, "", false))
	tuitest.Golden(t, "applying", ApplyingPage(chrome()))
	tuitest.Golden(t, "failed", ErrorPage(chrome(), setTimedOut))
}

// The form becomes netd settings: a static address on its own family, the
// other left as it comes, and the DNS server.
func TestTheFormsSettings(t *testing.T) {
	f := form{port: "ens192", address: netip.MustParsePrefix("2001:db8::10/64"), gateway: netip.MustParseAddr("2001:db8::1"), dns: netip.MustParseAddr("2001:db8::53")}
	s := f.settings()
	if s.Management.IPv6.Mode != network.V6Static || s.Management.IPv4.Mode != network.V4DHCP || len(s.DNS) != 1 || network.Validate(s) != nil {
		t.Fatalf("%+v: %v", s, network.Validate(s))
	}
}

// Each field takes only what fits it.
func TestFieldsRefuseWhatDoesntFit(t *testing.T) {
	f := form{nics: nics, port: "ens192"}
	for _, c := range []struct {
		field int
		in    string
	}{{fieldPort, "3"}, {fieldAddress, "192.0.2.10"}, {fieldAddress, "fe80::1/64"}, {fieldGateway, "gw"}, {fieldDNS, "dns"}} {
		if err := f.set(c.field, c.in); err == nil {
			t.Errorf("field %d took %q", c.field, c.in)
		}
	}
	if err := f.set(fieldAddress, "192.0.2.10/24"); err != nil {
		t.Fatal(err)
	}
	if err := f.set(fieldGateway, "2001:db8::1"); err == nil {
		t.Error("an IPv6 gateway for an IPv4 address")
	}
	if err := f.set(fieldPort, "2"); err != nil || f.port != "ens224" {
		t.Errorf("port %q: %v", f.port, err)
	}
}

// An address set by hand changes only the family it's on and, when one is
// typed, the DNS server: NTP, the host name, the search domains, the
// allow-list, the time zone, the proxy, the cluster ranges and the other
// family stay as the box has them.
func TestAnAddressSetByHandKeepsTheOtherSettings(t *testing.T) {
	base := network.Defaults("ens192")
	base.Management.IPv6 = network.Family6{Mode: network.V6Static, Address: netip.MustParsePrefix("2001:db8::10/64")}
	base.Hostname = "box1.sneakers.example.org"
	base.NTP = []string{"time.example.org"}
	base.Search = []string{"sneakers.example.org"}
	base.DNS = []netip.Addr{netip.MustParseAddr("192.0.2.53")}
	base.AllowList = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	base.TimeZone = "Europe/Paris"
	base.HTTPSProxy = "http://proxy.example.org:3128"
	base.Cluster.Pods = netip.MustParsePrefix("10.200.0.0/16") // scrub:allow=private-ip -- a cluster range
	f := form{port: "ens192", base: base, address: netip.MustParsePrefix("192.0.2.10/24"), gateway: netip.MustParseAddr("192.0.2.1")}
	s := f.settings()
	if s.Management.IPv4.Mode != network.V4Static || s.Management.IPv4.Address != f.address || s.Management.IPv6 != base.Management.IPv6 {
		t.Fatalf("management %+v", s.Management)
	}
	if s.Hostname != base.Hostname || len(s.NTP) != 1 || len(s.Search) != 1 || len(s.AllowList) != 1 || s.TimeZone != base.TimeZone || s.HTTPSProxy != base.HTTPSProxy || s.Cluster != base.Cluster {
		t.Fatalf("lost a setting: %+v", s)
	}
	if len(s.DNS) != 1 || s.DNS[0] != base.DNS[0] {
		t.Fatalf("dns %v, want the box's when none is typed", s.DNS)
	}
	f.dns = netip.MustParseAddr("192.0.2.54")
	if s := f.settings(); len(s.DNS) != 1 || s.DNS[0] != f.dns {
		t.Fatalf("dns %v, want the typed one", s.DNS)
	}
	// Another port starts that port's families afresh; the rest stays.
	f.port = "ens224"
	if s := f.settings(); s.Management.Name != "ens224" || s.Management.IPv6.Mode != network.V6SLAAC || s.Hostname != base.Hostname || len(s.NTP) != 1 {
		t.Fatalf("another port %+v", s)
	}
}

// slowNet is netd when it stops answering: each call marked here blocks
// until its context ends, or until release closes.
type slowNet struct {
	*consoletest.Network
	interfaces, set, checks bool
	release                 chan struct{}
}

func stuck(mark func(*slowNet)) *slowNet {
	n := &slowNet{Network: &consoletest.Network{}, release: make(chan struct{})}
	mark(n)
	return n
}

func (n *slowNet) block(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-n.release:
		return nil
	}
}

func (n *slowNet) Interfaces(ctx context.Context) ([]sources.NIC, error) {
	if n.interfaces {
		return nil, n.block(ctx)
	}
	return n.Network.Interfaces(ctx)
}

func (n *slowNet) Set(ctx context.Context, s network.Settings) (string, int, error) {
	if n.set {
		return "", 0, n.block(ctx)
	}
	return n.Network.Set(ctx, s)
}

func (n *slowNet) Checks(ctx context.Context) ([]sources.Check, error) {
	if n.checks {
		if err := n.block(ctx); err != nil {
			return nil, err
		}
	}
	return n.Network.Checks(ctx)
}

type editResult struct {
	kept bool
	err  error
}

// edit runs the editor on n and returns what it ended with.
func edit(t *testing.T, n sources.Network, set, checks time.Duration) (*tuitest.Driver, <-chan editResult) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d := tuitest.New(t)
	out := make(chan editResult, 1)
	go func() {
		kept, err := Edit(ctx, d.UI, Deps{Chrome: chrome(), Network: n, SetTimeout: set, ChecksTimeout: checks, ReadTimeout: 20 * time.Millisecond})
		out <- editResult{kept, err}
	}()
	return d, out
}

// fill types the whole form: the port, the address, no gateway, no DNS.
func fill(t *testing.T, d *tuitest.Driver) {
	t.Helper()
	d.Expect(t, "Port: ")
	d.Type(t, "")
	d.Expect(t, "Address: ")
	d.Type(t, "192.0.2.10/24")
	d.Expect(t, "Gateway: ")
	d.Type(t, "")
	d.Expect(t, "DNS server: ")
	d.Type(t, "")
}

func ended(t *testing.T, out <-chan editResult) editResult {
	t.Helper()
	select {
	case r := <-out:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("the editor never ended")
	}
	return editResult{}
}

// A Set that never answers runs out of time: the console says so and
// leaves the editor, where the dashboard takes over.
func TestASetThatNeverAnswersLeavesTheEditor(t *testing.T) {
	d, out := edit(t, stuck(func(n *slowNet) { n.set = true }), 20*time.Millisecond, time.Minute)
	fill(t, d)
	d.Expect(t, "Setting the address")
	d.Expect(t, "didn't answer in time")
	d.Type(t, "")
	if r := ended(t, out); r.kept || r.err != nil {
		t.Fatalf("%+v, want back to the console", r)
	}
}

// While Checks is running the page is up and takes its keys.
func TestTheChecksPageTakesKeysWhileChecksRun(t *testing.T) {
	n := stuck(func(n *slowNet) { n.checks = true })
	d, out := edit(t, n, time.Minute, time.Minute)
	fill(t, d)
	f := d.Expect(t, "Checking the network")
	if !strings.Contains(f, "Q  Leave") {
		t.Fatalf("no way out:\n%s", f)
	}
	d.Type(t, "e")
	fill(t, d)
	d.Expect(t, "Checking the network")
	d.Type(t, "q")
	if r := ended(t, out); r.kept || r.err != nil {
		t.Fatalf("%+v, want back to the console", r)
	}
	if len(n.Tokens()) != 0 {
		t.Fatalf("leaving kept the address: %v", n.Tokens())
	}
}

// Checks that finish in the background reach the page, and Enter keeps the
// address.
func TestChecksFinishingInTheBackgroundShowAndTheAddressIsKept(t *testing.T) {
	n := stuck(func(n *slowNet) { n.checks = true })
	n.SetResults([]sources.Check{{Name: "gateway", State: sources.CheckOK}})
	d, out := edit(t, n, time.Minute, time.Minute)
	fill(t, d)
	d.Expect(t, "Checking the network")
	close(n.release)
	d.Expect(t, "Use these settings")
	d.Type(t, "")
	if r := ended(t, out); !r.kept || r.err != nil {
		t.Fatalf("%+v, want it kept", r)
	}
}

// A Checks that never answers runs out of time and leaves the editor too.
func TestChecksThatNeverAnswerLeaveTheEditor(t *testing.T) {
	d, out := edit(t, stuck(func(n *slowNet) { n.checks = true }), time.Minute, 20*time.Millisecond)
	fill(t, d)
	d.Expect(t, "didn't finish in time")
	d.Type(t, "")
	if r := ended(t, out); r.kept || r.err != nil {
		t.Fatalf("%+v, want back to the console", r)
	}
}

// With no port list there's nothing to edit, and that isn't the end of the
// console: an error from Edit stops it.
func TestNoPortListLeavesTheEditor(t *testing.T) {
	d, out := edit(t, stuck(func(n *slowNet) { n.interfaces = true }), 20*time.Millisecond, time.Minute)
	d.Expect(t, "can't be listed")
	d.Type(t, "")
	if r := ended(t, out); r.kept || r.err != nil {
		t.Fatalf("%+v, want back to the console", r)
	}
}

// The console ending still ends the editor with its error.
func TestTheConsoleEndingEndsTheEditor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := tuitest.New(t)
	_, err := Edit(ctx, d.UI, Deps{Chrome: chrome(), Network: stuck(func(n *slowNet) { n.interfaces = true })})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}

func TestTheDeadlines(t *testing.T) {
	d := Deps{}.withDefaults()
	if d.SetTimeout != 15*time.Second || d.ChecksTimeout != 20*time.Second || d.ReadTimeout != 5*time.Second {
		t.Fatalf("set %v, checks %v, read %v", d.SetTimeout, d.ChecksTimeout, d.ReadTimeout)
	}
}
