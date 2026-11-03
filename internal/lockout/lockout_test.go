// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package lockout_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/lockout"
)

var t0 = time.Date(2026, 10, 7, 14, 0, 0, 0, time.UTC)

// three is the lowest limit an owner can set, which most tests here use.
var three = lockout.Rule{Mode: lockout.Timed, MaxFailures: 3}

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
	r := b.Fail("alice", "192.0.2.50", t0, three)
	if r.AttemptsLeft != 2 || !r.LockedUntil.IsZero() {
		t.Fatalf("after one failure %+v", r)
	}
	b.Fail("alice", "192.0.2.50", t0.Add(5*time.Minute), three)
	r = b.Fail("alice", "192.0.2.51", t0.Add(14*time.Minute), three)
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
	b.Fail("alice", "192.0.2.50", t0, three)
	b.Fail("alice", "192.0.2.50", t0.Add(10*time.Minute), three)
	r := b.Fail("alice", "192.0.2.50", t0.Add(16*time.Minute), three)
	if r.AttemptsLeft != 1 {
		t.Fatalf("the first failure fell out of the window: %+v", r)
	}
}

func TestASuccessResetsTheCount(t *testing.T) {
	b, _ := open(t)
	b.Fail("alice", "192.0.2.50", t0, three)
	b.Fail("alice", "192.0.2.50", t0.Add(time.Minute), three)
	b.Succeed("alice", t0.Add(2*time.Minute))
	if r := b.Fail("alice", "192.0.2.50", t0.Add(3*time.Minute), three); r.AttemptsLeft != 2 {
		t.Fatalf("a success didn't reset the count: %+v", r)
	}
}

func TestUntilUnlockedWaitsForAnOwner(t *testing.T) {
	b, _ := open(t)
	for i := range 3 {
		b.Fail("alice", "192.0.2.50", t0.Add(time.Duration(i)*time.Minute), lockout.Rule{Mode: lockout.UntilUnlocked, MaxFailures: 3})
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
		b.Fail("", "192.0.2.66", t0.Add(time.Duration(i)*time.Second), three)
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
		b.Fail("alice", "192.0.2.50", t0.Add(time.Duration(i)*time.Minute), three)
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

// A rule with no limit locks after the default 5 failures, and the lock
// and the Access page say 5.
func TestNoLimitMeansFive(t *testing.T) {
	b, _ := open(t)
	for i := range 4 {
		r := b.Fail("alice", "192.0.2.50", t0.Add(time.Duration(i)*time.Minute), lockout.Rule{Mode: lockout.Timed})
		if r.AttemptsLeft != 4-i || !r.LockedUntil.IsZero() {
			t.Fatalf("after %d failures %+v", i+1, r)
		}
	}
	r := b.Fail("alice", "192.0.2.50", t0.Add(4*time.Minute), lockout.Rule{Mode: lockout.Timed})
	if r.AttemptsLeft != 0 || r.LockedUntil.IsZero() {
		t.Fatalf("the fifth failure didn't lock: %+v", r)
	}
	err := b.Check("alice", "192.0.2.50", t0.Add(5*time.Minute))
	if !codes.Is(err, codes.AccessLocked) || !strings.Contains(err.Error(), "after 5 failed tries") {
		t.Fatalf("the lock: %v", err)
	}
	if st := b.State("alice", t0.Add(5*time.Minute)); st.Failures != 5 {
		t.Fatalf("state %+v", st)
	}
	if lockout.DefaultMaxFailures != 5 {
		t.Fatalf("the default is %d", lockout.DefaultMaxFailures)
	}
}

func TestALimitOfFourLocksAtTheFourth(t *testing.T) {
	b, _ := open(t)
	four := lockout.Rule{Mode: lockout.Timed, MaxFailures: 4}
	for i := range 3 {
		if r := b.Fail("alice", "192.0.2.50", t0.Add(time.Duration(i)*time.Minute), four); r.AttemptsLeft != 3-i {
			t.Fatalf("after %d failures %+v", i+1, r)
		}
	}
	if r := b.Fail("alice", "192.0.2.50", t0.Add(3*time.Minute), four); r.LockedUntil.IsZero() {
		t.Fatalf("the fourth failure didn't lock: %+v", r)
	}
	if err := b.Check("alice", "192.0.2.50", t0.Add(4*time.Minute)); !strings.Contains(err.Error(), "after 4 failed tries") {
		t.Fatalf("the lock: %v", err)
	}
}

// Lowering the limit locks nobody by itself; the next failure is judged
// by the new limit.
func TestALowerLimitAppliesFromTheNextFailure(t *testing.T) {
	b, _ := open(t)
	five := lockout.Rule{Mode: lockout.Timed, MaxFailures: 5}
	for i := range 3 {
		b.Fail("alice", "192.0.2.50", t0.Add(time.Duration(i)*time.Minute), five)
	}
	if err := b.Check("alice", "192.0.2.50", t0.Add(4*time.Minute)); err != nil {
		t.Fatalf("three failures under a limit of five: %v", err)
	}
	if r := b.Fail("alice", "192.0.2.50", t0.Add(5*time.Minute), three); r.LockedUntil.IsZero() || r.AttemptsLeft != 0 {
		t.Fatalf("the next failure under a limit of three: %+v", r)
	}
	if err := b.Check("alice", "192.0.2.50", t0.Add(6*time.Minute)); !strings.Contains(err.Error(), "after 3 failed tries") {
		t.Fatalf("the lock: %v", err)
	}
}

// A lock written before the limit was a setting came from 3 failures.
func TestALockFromAnOlderBookSaysThree(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lockout.json")
	until := t0.Add(15 * time.Minute).Format(time.RFC3339)
	if err := os.WriteFile(p, []byte(`{"accounts":{"alice":{"lockedUntil":"`+until+`"}},"sources":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := lockout.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Check("alice", "192.0.2.50", t0); !strings.Contains(err.Error(), "after 3 failed tries") {
		t.Fatalf("the lock: %v", err)
	}
	if st := b.State("alice", t0); st.Failures != 3 {
		t.Fatalf("state %+v", st)
	}
}
