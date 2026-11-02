// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd_test

import (
	"context"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

// Setup's host name is checked through the box's own DNS servers, in the
// settings' order, until one answers.
func TestResolveAsksTheBoxsDNSServersInTurn(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	b.sys.dnsNames = map[string][]netip.Addr{"appliance.example.org": {netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}}
	b.sys.dnsErr[netip.MustParseAddr("192.0.2.53")] = errDown
	b.start()

	got, err := b.d.Resolve(context.Background(), "Appliance.Example.org.")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Found || got.Server != netip.MustParseAddr("2001:db8::53") || len(got.Addrs) != 2 || got.Addrs[0].String() != "192.0.2.10" {
		t.Fatalf("%+v", got)
	}
	b.sys.mu.Lock()
	asked := slices.Clone(b.sys.dnsAsked)
	b.sys.mu.Unlock()
	if !slices.Equal(asked, []string{"192.0.2.53 lookup appliance.example.org", "2001:db8::53 lookup appliance.example.org"}) {
		t.Fatalf("asked %v", asked)
	}

	missing, err := b.d.Resolve(context.Background(), "nothere.example.org")
	if err != nil || missing.Found || len(missing.Addrs) != 0 {
		t.Fatalf("%+v %v", missing, err)
	}
}

func TestResolveSaysWhenNoDNSServerAnswers(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	for _, s := range []string{"192.0.2.53", "2001:db8::53"} {
		b.sys.dnsErr[netip.MustParseAddr(s)] = errDown
	}
	b.start()
	if _, err := b.d.Resolve(context.Background(), "appliance.example.org"); !codes.Is(err, codes.NetDNS) {
		t.Fatalf("want NET_DNS, got %v", err)
	}

	none := newBox(t)
	s := static("eth0")
	s.DNS = nil
	none.writeSettings("network.yaml", s)
	none.start()
	if _, err := none.d.Resolve(context.Background(), "appliance.example.org"); !codes.Is(err, codes.NetDNS) || !strings.Contains(err.Error(), "no DNS server") {
		t.Fatalf("want NET_DNS for no server, got %v", err)
	}
}

func TestResolveTakesOnlyAFullyQualifiedName(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	b.start()
	if _, err := b.d.Resolve(context.Background(), "appliance"); !codes.Is(err, codes.NetInvalid) || network.Field(err) != "hostname" {
		t.Fatalf("want NET_INVALID on hostname, got %v", err)
	}
}

// The host name alone is set and kept at once: no window, nothing else in
// the settings moves, and it's saved.
func TestSetHostnameSetsTheNameAloneAndKeepsIt(t *testing.T) {
	b := newBox(t)
	s := static("eth0")
	s.Hostname = ""
	b.writeSettings("network.yaml", s)
	b.start()

	prev, err := b.d.SetHostname("Appliance.Example.org.")
	if err != nil || prev != "" {
		t.Fatalf("%q %v", prev, err)
	}
	got, pending := b.d.Get()
	if pending || got.Hostname != "appliance.example.org" {
		t.Fatalf("pending %v, host name %q", pending, got.Hostname)
	}
	want := s
	want.Hostname = "appliance.example.org"
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("other settings moved: %+v", got)
	}
	if b.saved().Hostname != "appliance.example.org" {
		t.Fatal("not saved")
	}
	if _, ok := b.d.PendingChange(); ok {
		t.Fatal("a window was opened")
	}
	waitFor(t, func() bool { return b.sys.host() == "appliance.example.org" })
	if st := b.d.Status(); st.Hostname != "appliance.example.org" {
		t.Fatalf("Status says %q", st.Hostname)
	}

	again, err := b.d.SetHostname("other.example.org")
	if err != nil || again != "appliance.example.org" {
		t.Fatalf("%q %v", again, err)
	}
	if _, err := b.d.SetHostname("no spaces allowed"); !codes.Is(err, codes.NetInvalid) {
		t.Fatalf("want NET_INVALID, got %v", err)
	}
}

func TestSetHostnameWaitsForAPendingChange(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	b.start()
	next := static("eth0")
	next.AllowList = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if _, err := b.d.Set(next); err != nil {
		t.Fatal(err)
	}
	if _, err := b.d.SetHostname("appliance.example.org"); !codes.Is(err, codes.NetInvalid) || network.Field(err) != "pending" {
		t.Fatalf("want NET_INVALID on pending, got %v", err)
	}
}

func TestResolveAndSetHostnameOverConnect(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	b.sys.dnsNames = map[string][]netip.Addr{"appliance.example.org": {netip.MustParseAddr("192.0.2.10")}}
	b.start()
	c := serve(t, b)
	ctx := context.Background()

	res, err := c.Resolve(ctx, connect.NewRequest(&netdv1.ResolveRequest{Name: "appliance.example.org"}))
	if err != nil || !res.Msg.GetFound() || !slices.Equal(res.Msg.GetAddresses(), []string{"192.0.2.10"}) || res.Msg.GetServer() != "192.0.2.53" {
		t.Fatalf("%v %v", res, err)
	}
	if _, err := c.Resolve(ctx, connect.NewRequest(&netdv1.ResolveRequest{Name: "x"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a bad name: %v", err)
	}
	set, err := c.SetHostname(ctx, connect.NewRequest(&netdv1.SetHostnameRequest{Hostname: "appliance.example.org"}))
	if err != nil || set.Msg.GetPrevious() != "appliance.sneakers.example.org" {
		t.Fatalf("%v %v", set, err)
	}
	if b.saved().Hostname != "appliance.example.org" {
		t.Fatal("not saved")
	}
}
