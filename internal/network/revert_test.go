// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package network_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

func named(host string) network.Settings {
	s := base()
	s.Hostname = host + ".example.org"
	return s
}

type recorder struct{ applied []string }

func (r *recorder) apply(s network.Settings) error {
	r.applied = append(r.applied, s.Hostname[:len(s.Hostname)-len(".example.org")])
	return nil
}

func TestRevertWithoutConfirm(t *testing.T) {
	clk := clock.NewFake()
	var reverted error
	r := network.NewReverter(clk, network.RevertOptions{OnRevert: func(_ network.Settings, err error) { reverted = err }})
	var rec recorder
	_, err := r.Apply(named("old"), named("new"), rec.apply)
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(119 * time.Second)
	if !slices.Equal(rec.applied, []string{"new"}) {
		t.Fatalf("reverted early: %v", rec.applied)
	}
	clk.Advance(2 * time.Second)
	if !slices.Equal(rec.applied, []string{"new", "old"}) {
		t.Fatalf("applied %v, want new then old", rec.applied)
	}
	if !codes.Is(reverted, codes.NetReverted) {
		t.Fatalf("OnRevert got %v", reverted)
	}
	if r.Pending() {
		t.Fatal("still pending after the revert")
	}
}

func TestConfirmKeeps(t *testing.T) {
	clk := clock.NewFake()
	r := network.NewReverter(clk)
	var rec recorder
	token, err := r.Apply(named("old"), named("new"), rec.apply)
	if err != nil {
		t.Fatal(err)
	}
	assertFieldErr(t, r.Confirm("not-the-token"), "NET_INVALID", "token")
	if err := r.Confirm(token); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Hour)
	if !slices.Equal(rec.applied, []string{"new"}) {
		t.Fatalf("a confirmed change was reverted: %v", rec.applied)
	}
}

func TestConfirmAfterRevert(t *testing.T) {
	clk := clock.NewFake()
	r := network.NewReverter(clk)
	var rec recorder
	token, _ := r.Apply(named("old"), named("new"), rec.apply)
	clk.Advance(network.RevertAfter)
	if err := r.Confirm(token); !codes.Is(err, codes.NetReverted) {
		t.Fatalf("confirm after revert: %v", err)
	}
}

func TestOnePendingChange(t *testing.T) {
	clk := clock.NewFake()
	r := network.NewReverter(clk)
	var rec recorder
	if _, err := r.Apply(named("old"), named("new"), rec.apply); err != nil {
		t.Fatal(err)
	}
	_, err := r.Apply(named("new"), named("newer"), rec.apply)
	assertFieldErr(t, err, "NET_INVALID", "pending")
	if !slices.Equal(rec.applied, []string{"new"}) {
		t.Fatalf("the refused change was applied: %v", rec.applied)
	}
}

func TestInvalidChangeNotApplied(t *testing.T) {
	r := network.NewReverter(clock.NewFake())
	var rec recorder
	bad := named("new")
	bad.DNS = addrs("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4")
	_, err := r.Apply(named("old"), bad, rec.apply)
	assertFieldErr(t, err, "NET_INVALID", "dns")
	if len(rec.applied) != 0 || r.Pending() {
		t.Fatal("an invalid change was applied")
	}
}

func TestFailedApplyRestoresPrevious(t *testing.T) {
	r := network.NewReverter(clock.NewFake())
	var got []string
	boom := errors.New("netlink refused")
	apply := func(s network.Settings) error {
		got = append(got, s.Hostname)
		if s.Hostname == "new.example.org" {
			return boom
		}
		return nil
	}
	if _, err := r.Apply(named("old"), named("new"), apply); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if !slices.Equal(got, []string{"new.example.org", "old.example.org"}) || r.Pending() {
		t.Fatalf("applied %v", got)
	}
}

func TestPendingChangeAfterAReload(t *testing.T) {
	clk := clock.NewFake()
	r := network.NewReverter(clk)
	var rec recorder
	if _, ok := r.PendingChange(); ok {
		t.Fatal("nothing pending yet")
	}
	token, err := r.Apply(named("old"), named("new"), rec.apply)
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(30 * time.Second)
	p, ok := r.PendingChange()
	if !ok || p.Token != token || p.ID == "" || p.ID == token {
		t.Fatalf("pending %+v %v, want the token and a separate id", p, ok)
	}
	if left := p.Left(clk.Now()); left != 90*time.Second {
		t.Fatalf("left %v, want 90s", left)
	}
	if _, ok := r.Last(); ok {
		t.Fatal("no change has ended yet")
	}
	if err := r.Confirm(p.Token); err != nil {
		t.Fatal(err)
	}
	last, ok := r.Last()
	if !ok || last.ID != p.ID || last.Reverted || !last.At.Equal(clk.Now()) {
		t.Fatalf("last %+v %v, want the confirmed change", last, ok)
	}
}

func TestLastRecordsTheRevert(t *testing.T) {
	clk := clock.NewFake()
	r := network.NewReverter(clk)
	var rec recorder
	if _, err := r.Apply(named("old"), named("new"), rec.apply); err != nil {
		t.Fatal(err)
	}
	p, _ := r.PendingChange()
	clk.Advance(network.RevertAfter)
	last, ok := r.Last()
	if !ok || last.ID != p.ID || !last.Reverted {
		t.Fatalf("last %+v %v, want the reverted change", last, ok)
	}
}
