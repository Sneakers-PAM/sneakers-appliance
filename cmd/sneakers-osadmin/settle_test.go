// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect" // scrub:allow=fqdn -- a Go module path
	log "github.com/Bugs5382/go-log"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
)

// fakeBinding answers each GetBinding with the next address set, staying
// on the last.
type fakeBinding struct {
	accessv1connect.BindingServiceClient
	mu    sync.Mutex
	sets  [][]string
	calls int
}

func (f *fakeBinding) GetBinding(context.Context, *connect.Request[accessv1.GetBindingRequest]) (*connect.Response[accessv1.GetBindingResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := min(f.calls, len(f.sets)-1)
	f.calls++
	return connect.NewResponse(&accessv1.GetBindingResponse{Hostname: "box1.sneakers.example.org", ManagementAddresses: f.sets[i]}), nil
}

// The console shows the first certificate's fingerprint for a person to
// check, so it's made for the set the addresses settle on, not the first
// address to arrive: IPv6 comes seconds after the DHCP lease.
func TestTheFirstCertificateWaitsForTheAddressesToSettle(t *testing.T) {
	v4, v6 := "192.0.2.10", "2001:db8::10"
	b := &fakeBinding{sets: [][]string{{v4}, {v4}, {v4, v6}}}
	_, addrs, err := settleAddresses(context.Background(), b, log.Nop(), 40*time.Millisecond, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{v4, v6}
	slices.Sort(want)
	if !slices.Equal(addrs, want) {
		t.Fatalf("%v, want %v", addrs, want)
	}
}

func TestSettlingStopsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := &fakeBinding{sets: [][]string{{"192.0.2.10"}}}
	if _, _, err := settleAddresses(ctx, b, log.Nop(), time.Hour, time.Millisecond); err == nil {
		t.Fatal("no error")
	}
}
