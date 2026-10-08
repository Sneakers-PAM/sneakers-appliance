// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package lockout_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/lockout"
)

var t0 = time.Date(2026, 10, 7, 14, 0, 0, 0, time.UTC)

func open(t *testing.T) (*lockout.Book, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "lockout.json")
	b, err := lockout.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	return b, p
}

func TestThreeFailuresInFifteenMinutesLockForFifteen(t *testing.T) {
	b, _ := open(t)
	r := b.Fail("alice", "192.0.2.50", t0, lockout.Timed)
	if r.AttemptsLeft != 2 || !r.LockedUntil.IsZero() {
		t.Fatalf("after one failure %+v", r)
	}
	b.Fail("alice", "192.0.2.50", t0.Add(5*time.Minute), lockout.Timed)
	r = b.Fail("alice", "192.0.2.51", t0.Add(14*time.Minute), lockout.Timed)
	if r.AttemptsLeft != 0 || !r.LockedUntil.Equal(t0.Add(29*time.Minute)) {
		t.Fatalf("after three failures %+v", r)
	}
	if err := b.Check("alice", "192.0.2.99", t0.Add(20*time.Minute)); !codes.Is(err, codes.AccessLocked) {
		t.Fatalf("a locked account from anywhere: %v", err)
	}
	if err := b.Check("alice", "192.0.2.99", t0.Add(29*time.Minute)); err != nil {
		t.Fatalf("the lock should be over: %v", err)
	}
	if err := b.Check("bob", "192.0.2.50", t0.Add(20*time.Minute)); err != nil {
		t.Fatalf("another admin is locked too: %v", err)
	}
}

func TestFailuresOutsideTheWindowDontCount(t *testing.T) {
	b, _ := open(t)
	b.Fail("alice", "192.0.2.50", t0, lockout.Timed)
	b.Fail("alice", "192.0.2.50", t0.Add(10*time.Minute), lockout.Timed)
	r := b.Fail("alice", "192.0.2.50", t0.Add(16*time.Minute), lockout.Timed)
	if r.AttemptsLeft != 1 {
		t.Fatalf("the first failure fell out of the window: %+v", r)
	}
}

func TestASuccessResetsTheCount(t *testing.T) {
	b, _ := open(t)
	b.Fail("alice", "192.0.2.50", t0, lockout.Timed)
	b.Fail("alice", "192.0.2.50", t0.Add(time.Minute), lockout.Timed)
	b.Succeed("alice", t0.Add(2*time.Minute))
	if r := b.Fail("alice", "192.0.2.50", t0.Add(3*time.Minute), lockout.Timed); r.AttemptsLeft != 2 {
		t.Fatalf("a success didn't reset the count: %+v", r)
	}
}

func TestUntilUnlockedWaitsForAnOwner(t *testing.T) {
	b, _ := open(t)
	for i := range 3 {
		b.Fail("alice", "192.0.2.50", t0.Add(time.Duration(i)*time.Minute), lockout.UntilUnlocked)
	}
	err := b.Check("alice", "192.0.2.50", t0.Add(48*time.Hour))
	if !codes.Is(err, codes.AccessLocked) {
		t.Fatalf("still locked two days later: %v", err)
	}
	r := lockout.RefusalOf(err)
	if !r.UntilUnlocked {
		t.Fatalf("refusal %+v", r)
	}
	if !b.Unlock("alice") {
		t.Fatal("Unlock found no lock")
	}
	if err := b.Check("alice", "192.0.2.50", t0.Add(48*time.Hour)); err != nil {
		t.Fatalf("after unlock: %v", err)
	}
}

func TestOneSourceIsThrottledAcrossNames(t *testing.T) {
	b, _ := open(t)
	for i := range lockout.SourceMax {
		b.Fail("", "192.0.2.66", t0.Add(time.Duration(i)*time.Second), lockout.Timed)
	}
	err := b.Check("bob", "192.0.2.66", t0.Add(time.Minute))
	if !codes.Is(err, codes.AccessThrottled) {
		t.Fatalf("a busy source: %v", err)
	}
	if r := lockout.RefusalOf(err); r.RetryAfter.IsZero() {
		t.Fatalf("no retry time: %+v", r)
	}
	if err := b.Check("bob", "192.0.2.67", t0.Add(time.Minute)); err != nil {
		t.Fatalf("another source is throttled: %v", err)
	}
	if err := b.Check("bob", "192.0.2.66", t0.Add(time.Minute+lockout.SourceHold)); err != nil {
		t.Fatalf("the throttle never ends: %v", err)
	}
}

func TestTheBookSurvivesARestart(t *testing.T) {
	b, p := open(t)
	for i := range 3 {
		b.Fail("alice", "192.0.2.50", t0.Add(time.Duration(i)*time.Minute), lockout.Timed)
	}
	b.SetStep("alice", 42)
	again, err := lockout.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Check("alice", "192.0.2.50", t0.Add(5*time.Minute)); !codes.Is(err, codes.AccessLocked) {
		t.Fatalf("a restart dropped the lock: %v", err)
	}
	if again.LastStep("alice") != 42 {
		t.Fatal("a restart dropped the last TOTP step")
	}
	st := again.State("alice", t0.Add(5*time.Minute))
	if st.Failures != 3 || st.LockedUntil.IsZero() {
		t.Fatalf("state %+v", st)
	}
	again.Forget("alice")
	if again.LastStep("alice") != 0 {
		t.Fatal("Forget kept the account")
	}
}
