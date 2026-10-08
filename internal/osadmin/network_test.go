// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
)

func TestAReloadedPageCanStillConfirm(t *testing.T) {
	b := newBox(t, true)
	ctx := context.Background()
	alice := b.browser()
	alice.signIn("alice")
	nc := osadminv1connect.NewNetworkServiceClient(alice.hc, b.ts.URL)
	set := defaultSettings()
	set.Ntp = []string{"192.0.2.123"}
	res, err := nc.SetNetwork(ctx, connect.NewRequest(&osadminv1.SetNetworkRequest{Settings: set}))
	if err != nil {
		t.Fatal(err)
	}
	g, err := nc.GetNetwork(ctx, connect.NewRequest(&osadminv1.GetNetworkRequest{}))
	if err != nil || g.Msg.GetPendingToken() != res.Msg.GetToken() || g.Msg.GetPendingChangeId() != "chg-1" || g.Msg.GetRevertSecondsLeft() != 95 {
		t.Fatalf("an owner's GetNetwork %v %v, want the token, the change and the seconds left", g, err)
	}

	bob := b.browser()
	bob.signIn("bob")
	bg, err := osadminv1connect.NewNetworkServiceClient(bob.hc, b.ts.URL).GetNetwork(ctx, connect.NewRequest(&osadminv1.GetNetworkRequest{}))
	if err != nil || !bg.Msg.GetPending() || bg.Msg.GetPendingToken() != "" || bg.Msg.GetRevertSecondsLeft() != 95 {
		t.Fatalf("an admin's GetNetwork %v %v, want pending and the seconds but no token", bg, err)
	}

	if _, err := nc.ConfirmNetwork(ctx, connect.NewRequest(&osadminv1.ConfirmNetworkRequest{Token: g.Msg.GetPendingToken()})); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, b.log, "network.confirm"); e.Outcome != "ok" || e.Detail["change"] != "chg-1" {
		t.Fatalf("confirm entry %+v, want the change id", e)
	}
	if e := lastEntry(t, b.log, "network.set"); e.Detail["change"] != "chg-1" {
		t.Fatalf("set entry %+v, want the change id", e)
	}
}

func TestApplySaysWhenTheAddressMoves(t *testing.T) {
	cases := []struct {
		name    string
		change  func(*netdv1.Settings)
		moves   bool
		url     string
		newCert bool
	}{
		{name: "dns only", change: func(s *netdv1.Settings) { s.Dns = []string{"192.0.2.53"} }},
		{name: "host name", change: func(s *netdv1.Settings) { s.Hostname = "box2.example.org" }, newCert: true},
		{name: "static ipv4", change: func(s *netdv1.Settings) {
			s.Management.Ipv4 = &netdv1.Ipv4{Mode: netdv1.Ipv4Mode_IPV4_MODE_STATIC, Address: "192.0.2.20/24", Gateway: "192.0.2.1"}
		}, moves: true, url: "https://192.0.2.20:8443/", newCert: true},
		{name: "static ipv6", change: func(s *netdv1.Settings) {
			s.Management.Ipv6 = &netdv1.Ipv6{Mode: netdv1.Ipv6Mode_IPV6_MODE_STATIC, Address: "2001:db8::20/64"}
		}, moves: true, url: "https://[2001:db8::20]:8443/", newCert: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newBox(t, false)
			alice := b.browser()
			alice.signIn("alice")
			alice.stepUp("alice")
			set := defaultSettings()
			tc.change(set)
			res, err := osadminv1connect.NewNetworkServiceClient(alice.hc, b.ts.URL).SetNetwork(context.Background(), connect.NewRequest(&osadminv1.SetNetworkRequest{Settings: set}))
			if err != nil {
				t.Fatal(err)
			}
			if res.Msg.GetMovesManagement() != tc.moves || res.Msg.GetNewUrl() != tc.url || res.Msg.GetNewCertificate() != tc.newCert {
				t.Fatalf("moves %v url %q cert %v, want %v %q %v", res.Msg.GetMovesManagement(), res.Msg.GetNewUrl(), res.Msg.GetNewCertificate(), tc.moves, tc.url, tc.newCert)
			}
		})
	}
}

func TestTheRevertIsAudited(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	set := defaultSettings()
	set.Hostname = "box2.example.org"
	if _, err := osadminv1connect.NewNetworkServiceClient(alice.hc, b.ts.URL).SetNetwork(context.Background(), connect.NewRequest(&osadminv1.SetNetworkRequest{Settings: set})); err != nil {
		t.Fatal(err)
	}
	b.netd.revert()
	b.clk.Advance(130 * time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for {
		es, err := b.log.Entries()
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			if e.Action == "network.revert" {
				if e.Actor != "netd" || e.Target != "network" || e.Detail["change"] != "chg-1" || e.Code != "NET_REVERTED" {
					t.Fatalf("revert entry %+v", e)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("no network.revert entry")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
