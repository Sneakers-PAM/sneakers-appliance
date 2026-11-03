// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
)

// setLockoutLimit has alice (an owner) set the lockout limit on the
// Access page.
func setLockoutLimit(t *testing.T, b *box, limit int32) error {
	t.Helper()
	alice := b.browser()
	alice.signIn("alice")
	_, err := alice.access().SetAccessPolicy(context.Background(), connect.NewRequest(&osadminv1.SetAccessPolicyRequest{Policy: &osadminv1.AccessPolicy{
		LockoutMode: osadminv1.LockoutMode_LOCKOUT_MODE_TIMED, LockoutMaxFailures: limit, RootCodeMinutes: 10, RootSessionMinutes: 10, SshKeyValidDays: 365,
	}}))
	return err
}

// lockAfterThree sets the lowest lockout limit straight in the store, for
// the tests written around three failures.
func lockAfterThree(t *testing.T, b *box) {
	t.Helper()
	if err := b.store.Update(func(st *access.State) error { st.AccessPolicy.LockoutMaxFailures = 3; return nil }); err != nil {
		t.Fatal(err)
	}
}

// Five wrong passwords lock the account by default; four don't.
func TestFiveWrongPasswordsLockByDefault(t *testing.T) {
	b := newBox(t, false)
	br := b.browser()
	for i, left := range []int32{4, 3, 2, 1} {
		_, err := trySignIn(br, "alice", "not the password", b.code("alice"))
		if r := refusalOf(t, err); r.GetAttemptsLeft() != left || r.GetLockedUntil() != nil {
			t.Fatalf("try %d: %v", i, r)
		}
	}
	_, err := trySignIn(br, "alice", "not the password", b.code("alice"))
	if r := refusalOf(t, err); r.GetAttemptsLeft() != 0 || r.GetLockedUntil() == nil {
		t.Fatalf("the fifth failure: %v", r)
	}
	_, err = trySignIn(br, "alice", testPassword, b.code("alice"))
	symbolIn(t, err, connect.CodeResourceExhausted, "ACCESS_LOCKED")
	if !strings.Contains(err.Error(), "after 5 failed tries") {
		t.Fatalf("the lock message: %v", err)
	}
}

// Five wrong authenticator codes, with the right password, lock it too.
func TestFiveWrongCodesLockByDefault(t *testing.T) {
	b := newBox(t, false)
	br := b.browser()
	for i, left := range []int32{4, 3, 2, 1} {
		_, err := trySignIn(br, "alice", testPassword, "000000")
		if r := refusalOf(t, err); r.GetAttemptsLeft() != left {
			t.Fatalf("try %d: %v", i, r)
		}
	}
	_, err := trySignIn(br, "alice", testPassword, "000000")
	if r := refusalOf(t, err); r.GetLockedUntil() == nil {
		t.Fatalf("the fifth wrong code: %v", r)
	}
	if e := lastEntry(t, b.log, "access.lockout"); e.Target != "alice" {
		t.Fatalf("the lock isn't audited: %+v", e)
	}
}

// A wrong password and a wrong code count toward the same limit.
func TestWrongPasswordsAndCodesShareTheLimit(t *testing.T) {
	b := newBox(t, true)
	if err := setLockoutLimit(t, b, 4); err != nil {
		t.Fatal(err)
	}
	bob := b.browser()
	for i, try := range []struct {
		password, code string
		left           int32
	}{
		{"not the password", b.code("bob"), 3},
		{testPassword, "000000", 2},
		{"not the password", b.code("bob"), 1},
	} {
		_, err := trySignIn(bob, "bob", try.password, try.code)
		if r := refusalOf(t, err); r.GetAttemptsLeft() != try.left {
			t.Fatalf("try %d: %v", i, r)
		}
	}
	_, err := trySignIn(bob, "bob", testPassword, "000000")
	if r := refusalOf(t, err); r.GetLockedUntil() == nil {
		t.Fatalf("the fourth failure, a wrong code: %v", r)
	}
	_, err = trySignIn(bob, "bob", testPassword, b.code("bob"))
	symbolIn(t, err, connect.CodeResourceExhausted, "ACCESS_LOCKED")
	if !strings.Contains(err.Error(), "after 4 failed tries") {
		t.Fatalf("the lock message: %v", err)
	}
}

// The owner's limit is 3, 4 or 5; it's audited and read back on the Access
// page, 0 means the default, and anything else is refused.
func TestTheLockoutLimitIsAnAccessSetting(t *testing.T) {
	b := newBox(t, false)
	for _, bad := range []int32{1, 2, 6, -3} {
		err := setLockoutLimit(t, b, bad)
		symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_POLICY")
	}
	if err := setLockoutLimit(t, b, 3); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, b.log, "access.policy.set"); e.Outcome != "ok" || e.Detail["lockoutMaxFailures"] != "3" {
		t.Fatalf("the change isn't audited: %+v", e)
	}
	alice := b.browser()
	alice.signIn("alice")
	l, err := alice.access().ListAdmins(context.Background(), connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := l.Msg.GetAccessPolicy().GetLockoutMaxFailures(); got != 3 {
		t.Fatalf("the Access page reads %d", got)
	}
	if err := setLockoutLimit(t, b, 0); err != nil {
		t.Fatal(err)
	}
	if got := b.store.Read().AccessPolicy.LockoutMaxFailures; got != 5 {
		t.Fatalf("0 stored %d, not the default", got)
	}
}

// A box whose saved policy has no limit locks after 5, and the Access page
// shows 5.
func TestASavedPolicyWithNoLimitReadsAsFive(t *testing.T) {
	b := newBox(t, false)
	if err := b.store.Update(func(st *access.State) error { st.AccessPolicy.LockoutMaxFailures = 0; return nil }); err != nil {
		t.Fatal(err)
	}
	alice := b.browser()
	alice.signIn("alice")
	l, err := alice.access().ListAdmins(context.Background(), connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := l.Msg.GetAccessPolicy().GetLockoutMaxFailures(); got != 5 {
		t.Fatalf("the Access page reads %d", got)
	}
	_, err = trySignIn(b.browser(), "alice", "not the password", b.code("alice"))
	if r := refusalOf(t, err); r.GetAttemptsLeft() != 4 {
		t.Fatalf("the first failure: %v", r)
	}
}

// Lowering the limit locks nobody by itself; the next failure is judged
// by the new limit.
func TestALowerLimitAppliesFromTheNextFailure(t *testing.T) {
	b := newBox(t, true)
	bob := b.browser()
	for range 3 {
		_, _ = trySignIn(bob, "bob", "not the password", b.code("bob"))
	}
	if err := setLockoutLimit(t, b, 3); err != nil {
		t.Fatal(err)
	}
	alice := b.browser()
	alice.signIn("alice")
	l, err := alice.access().ListAdmins(context.Background(), connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range l.Msg.GetAdmins() {
		if a.GetName() == "bob" && (a.GetLockedUntil() != nil || a.GetLockedUntilUnlocked()) {
			t.Fatalf("lowering the limit locked bob: %v", a)
		}
	}
	_, err = trySignIn(bob, "bob", "not the password", b.code("bob"))
	if r := refusalOf(t, err); r.GetLockedUntil() == nil {
		t.Fatalf("the next failure under the lower limit: %v", r)
	}
	b.clk.Advance(15 * time.Minute)
	if _, err := trySignIn(bob, "bob", testPassword, b.code("bob")); err != nil {
		t.Fatalf("the lock should be over: %v", err)
	}
}
