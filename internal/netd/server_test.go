// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1/netdv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

func serve(t *testing.T, b *box) netdv1connect.NetworkServiceClient {
	t.Helper()
	path, h := b.d.Handler()
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return netdv1connect.NewNetworkServiceClient(srv.Client(), srv.URL)
}

func TestTheAPIOverConnect(t *testing.T) {
	b := newBox(t, eth0, eth1)
	b.writeSettings("network.yaml", static("eth0"))
	b.start()
	c := serve(t, b)
	ctx := context.Background()

	nics, err := c.ListInterfaces(ctx, connect.NewRequest(&netdv1.ListInterfacesRequest{}))
	if err != nil || len(nics.Msg.GetInterfaces()) != 2 || nics.Msg.GetInterfaces()[1].GetName() != "eth1" || !nics.Msg.GetInterfaces()[0].GetLinkUp() {
		t.Fatalf("interfaces %v %v", nics, err)
	}
	got, err := c.Get(ctx, connect.NewRequest(&netdv1.GetRequest{}))
	if err != nil || got.Msg.GetSettings().GetManagement().GetIpv4().GetAddress() != "192.0.2.10/24" {
		t.Fatalf("get %v %v", got, err)
	}

	bad := network.ToWire(static("eth0"))
	bad.Hostname = "not a name"
	_, err = c.Set(ctx, connect.NewRequest(&netdv1.SetRequest{Settings: bad}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument || !strings.Contains(err.Error(), "NET_INVALID") {
		t.Fatalf("invalid set: %v", err)
	}
	next := network.ToWire(static("eth0"))
	next.AllowList = []string{"192.0.2.0/24"}
	set, err := c.Set(ctx, connect.NewRequest(&netdv1.SetRequest{Settings: next}))
	if err != nil || set.Msg.GetToken() == "" || set.Msg.GetRevertAfterSeconds() != 120 {
		t.Fatalf("set %v %v", set, err)
	}
	if _, err := c.Confirm(ctx, connect.NewRequest(&netdv1.ConfirmRequest{Token: set.Msg.GetToken()})); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Confirm(ctx, connect.NewRequest(&netdv1.ConfirmRequest{Token: set.Msg.GetToken()})); !strings.Contains(err.Error(), "NET_REVERTED") {
		t.Fatalf("second confirm: %v", err)
	}

	if _, err := c.SetManagementPorts(ctx, connect.NewRequest(&netdv1.SetManagementPortsRequest{Ssh: true, Https: true})); err != nil {
		t.Fatal(err)
	}
	st, err := c.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
	if err != nil || !st.Msg.GetSshOpen() || !st.Msg.GetHttpsOpen() || !st.Msg.GetNtpSynced() || st.Msg.GetNtpOffsetMs() != 12 || len(st.Msg.GetManagementAddresses()) != 2 {
		t.Fatalf("status %v %v", st, err)
	}
	if _, err := c.SetServicePorts(ctx, connect.NewRequest(&netdv1.SetServicePortsRequest{Rules: []*netdv1.PortRule{{Protocol: "tcp", Port: 70000}}})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a bad port: %v", err)
	}

	checks, err := c.Checks(ctx, connect.NewRequest(&netdv1.ChecksRequest{}))
	if err != nil || len(checks.Msg.GetChecks()) == 0 || checks.Msg.GetChecks()[0].GetState() != netdv1.CheckState_CHECK_STATE_OK {
		t.Fatalf("checks %v %v", checks, err)
	}

	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stream, err := c.Watch(wctx, connect.NewRequest(&netdv1.WatchRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() {
		t.Fatalf("no first event: %v", stream.Err())
	}
	if a := stream.Msg().GetManagementAddresses(); len(a) != 2 || a[0] != "192.0.2.10/24" {
		t.Fatalf("first event %v", a)
	}
	b.sys.kernelAddr("eth0", "192.0.2.11/24", 0x80)
	if !stream.Receive() || len(stream.Msg().GetManagementAddresses()) != 3 {
		t.Fatalf("second event %v %v", stream.Msg(), stream.Err())
	}
}

func TestGetCarriesThePendingChange(t *testing.T) {
	b := newBox(t, eth0, eth1)
	b.writeSettings("network.yaml", static("eth0"))
	b.start()
	c := serve(t, b)
	ctx := context.Background()
	next := network.ToWire(static("eth0"))
	next.AllowList = []string{"192.0.2.0/24"}
	set, err := c.Set(ctx, connect.NewRequest(&netdv1.SetRequest{Settings: next}))
	if err != nil || set.Msg.GetChangeId() == "" {
		t.Fatalf("set %v %v", set, err)
	}
	b.clk.Advance(20 * time.Second)
	got, err := c.Get(ctx, connect.NewRequest(&netdv1.GetRequest{}))
	if err != nil || !got.Msg.GetPending() || got.Msg.GetToken() != set.Msg.GetToken() || got.Msg.GetChangeId() != set.Msg.GetChangeId() || got.Msg.GetSecondsLeft() != 100 {
		t.Fatalf("get %v %v, want the pending token, id and 100 seconds left", got, err)
	}
	b.clk.Advance(network.RevertAfter)
	got, err = c.Get(ctx, connect.NewRequest(&netdv1.GetRequest{}))
	if err != nil || got.Msg.GetPending() || got.Msg.GetToken() != "" || got.Msg.GetLast().GetChangeId() != set.Msg.GetChangeId() || !got.Msg.GetLast().GetReverted() {
		t.Fatalf("get after the revert %v %v", got, err)
	}
}
