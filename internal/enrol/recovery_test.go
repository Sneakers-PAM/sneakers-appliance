// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package enrol_test

import (
	"slices"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/enrol"
)

// Recover access: the console's window for an owner whose keys are all
// lost. The key it stores is marked as the console's recovery, can't
// approve elevations for 24 hours, and the acceptance is audited as a
// console recovery.
func TestRecoverAccessHoldsApprovals(t *testing.T) {
	f := newFixture(t)
	v, err := f.svc.OpenWith("alice", enrol.OpenOptions{Recovery: true})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Recovery {
		t.Fatal("the window doesn't say it's a recovery")
	}
	line, _ := key(t)
	k, err := f.svc.Submit(v.Code, line, "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Accept(k.ID, "yes"); err != nil {
		t.Fatal(err)
	}
	st := f.store.Read()
	a, _ := st.Admin("alice")
	if a.ApprovalHoldUntil == nil || a.ApprovalHoldUntil.Sub(f.clk.Now()) != 24*time.Hour {
		t.Fatalf("hold %v", a.ApprovalHoldUntil)
	}
	if len(a.Keys) != 1 || a.Keys[0].Via != access.ViaConsoleRecovery {
		t.Fatalf("keys %+v", a.Keys)
	}
	if !slices.Contains(f.audit.actions(), "access.console-recovery:ok") {
		t.Fatalf("audit %v", f.audit.actions())
	}
}

// Recover access is for owners only.
func TestRecoverAccessIsForOwners(t *testing.T) {
	f := newFixture(t)
	if err := f.store.Update(func(st *access.State) error {
		st.AddAdmin("bob", access.RoleAdmin, "alice", f.clk.Now())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.OpenWith("bob", enrol.OpenOptions{Recovery: true})
	wantCode(t, err, codes.AccessForbidden)
}

// A key typed or fetched on the console joins the window as a waiting key
// and is stored only with the typed yes, the same as one offered over SSH.
func TestAKeyOfferedOnTheConsoleWaitsForYes(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Open("alice"); err != nil {
		t.Fatal(err)
	}
	line, _ := key(t)
	k, err := f.svc.Offer(line, access.ViaTyped, "")
	if err != nil {
		t.Fatal(err)
	}
	if k.State != enrol.Waiting || k.Source != "console" || k.Via != access.ViaTyped {
		t.Fatalf("offered %+v", k)
	}
	if _, err := f.svc.Offer(line, access.ViaTyped, ""); err == nil {
		t.Fatal("the same key offered twice")
	}
	st := f.store.Read()
	if a, _ := st.Admin("alice"); len(a.Keys) != 0 {
		t.Fatal("stored before yes")
	}
	if _, err := f.svc.Accept(k.ID, "yes"); err != nil {
		t.Fatal(err)
	}
	st = f.store.Read()
	a, _ := st.Admin("alice")
	if len(a.Keys) != 1 || a.Keys[0].Via != access.ViaTyped || a.ApprovalHoldUntil != nil {
		t.Fatalf("admin %+v", a)
	}
	if f.svc.Get().AttemptsLeft != enrol.MaxAttempts {
		t.Fatal("an offer used up a code attempt")
	}
}

func TestOfferRefusesAWeakKeyAndAClosedWindow(t *testing.T) {
	f := newFixture(t)
	line, _ := key(t)
	_, err := f.svc.Offer(line, access.ViaTyped, "")
	wantCode(t, err, codes.EnrolClosed)
	if _, err := f.svc.Open("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Offer("ssh-dss AAAAB3NzaC1kc3MAAACBAP", access.ViaTyped, ""); err == nil {
		t.Fatal("a DSA key was taken")
	}
}
