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
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

func (b *box) sshLoginOf(admin string) osadmin.Local {
	return osadmin.Local{Admin: admin, KeyFP: b.keys[admin].fp, Source: "192.0.2.50"}
}

// An SSH login's TOTP check: the issued key, a fresh code, audited.
func TestTheSSHLoginChecksTheTOTPCode(t *testing.T) {
	b := newBox(t, false)
	l := b.sshLoginOf("alice")
	got, err := b.srv.VerifyLoginTotp(l, b.code("alice"))
	if err != nil || got.Admin != "alice" || got.ID == "" {
		t.Fatalf("%+v %v", got, err)
	}
	if e := lastEntry(t, b.log, "ssh.login"); e.Outcome != "ok" || e.KeyFP != l.KeyFP || e.Source != "192.0.2.50" {
		t.Fatalf("audit %+v", e)
	}
	if _, err := b.srv.VerifyLoginTotp(l, "000000"); !codes.Is(err, codes.AccessCredentials) {
		t.Fatalf("a wrong code: %v", err)
	}
	other := l
	other.KeyFP = "SHA256:not-an-issued-key"
	if _, err := b.srv.VerifyLoginTotp(other, b.code("alice")); !codes.Is(err, codes.AccessForbidden) {
		t.Fatalf("a key the box didn't issue: %v", err)
	}
	b.clk.Advance(400 * 24 * time.Hour)
	if _, err := b.srv.VerifyLoginTotp(l, b.code("alice")); err != nil {
		t.Fatalf("a key with no end date: %v", err)
	}
}

// The SSH TOTP check shares the :8443 lockout: three failures across both
// lock the account for both for 15 minutes; a success resets the count;
// the lock is audited.
func TestTheSSHAndWebLockoutIsOne(t *testing.T) {
	b := newBox(t, false)
	l := b.sshLoginOf("alice")
	_, _ = b.srv.VerifyLoginTotp(l, "000000")
	if _, err := b.srv.VerifyLoginTotp(l, b.code("alice")); err != nil {
		t.Fatal(err)
	}
	_, _ = b.srv.VerifyLoginTotp(l, "000000")
	_, _ = trySignIn(b.browser(), "alice", "wrong", b.code("alice"))
	_, err := b.srv.VerifyLoginTotp(l, "000000")
	if !codes.Is(err, codes.AccessCredentials) {
		t.Fatalf("the third failure: %v", err)
	}
	if _, err := b.srv.VerifyLoginTotp(l, b.code("alice")); !codes.Is(err, codes.AccessLocked) {
		t.Fatalf("locked over SSH: %v", err)
	}
	_, err = trySignIn(b.browser(), "alice", testPassword, b.code("alice"))
	symbolIn(t, err, connect.CodeResourceExhausted, "ACCESS_LOCKED")
	if e := lastEntry(t, b.log, "access.lockout"); e.Target != "alice" || e.Detail["surface"] != "ssh" {
		t.Fatalf("lock audit %+v", e)
	}
	b.clk.Advance(15 * time.Minute)
	if _, err := b.srv.VerifyLoginTotp(l, b.code("alice")); err != nil {
		t.Fatalf("after the lock: %v", err)
	}
}

func TestTheSSHLockCanWaitForAnOwner(t *testing.T) {
	b := newBox(t, true)
	if err := b.store.Update(func(st *access.State) error { st.AccessPolicy.LockoutMode = "until-unlocked"; return nil }); err != nil {
		t.Fatal(err)
	}
	l := b.sshLoginOf("bob")
	for range 3 {
		_, _ = b.srv.VerifyLoginTotp(l, "000000")
	}
	b.clk.Advance(24 * time.Hour)
	if _, err := b.srv.VerifyLoginTotp(l, b.code("bob")); !codes.Is(err, codes.AccessLocked) {
		t.Fatalf("still locked: %v", err)
	}
	alice := b.browser()
	alice.signIn("alice")
	if _, err := alice.access().UnlockAdmin(context.Background(), connect.NewRequest(&osadminv1.UnlockAdminRequest{Name: "bob"})); err != nil {
		t.Fatal(err)
	}
	if _, err := b.srv.VerifyLoginTotp(l, b.code("bob")); err != nil {
		t.Fatalf("after the unlock: %v", err)
	}
}

func rootShellClient(br *browser) osadminv1connect.RootShellServiceClient {
	return osadminv1connect.NewRootShellServiceClient(br.hc, br.b.ts.URL)
}

// The root-shell code page: the operator's own challenge, a fresh TOTP
// code, and a code that opens that challenge once.
func TestTheRootShellCodePage(t *testing.T) {
	b := newBox(t, true)
	b.store.Update(rosterOf("alice"))
	ctx := context.Background()
	if _, err := b.srv.BeginRootShell(b.sshLoginOf("bob"), ""); !codes.Is(err, codes.AccessForbidden) {
		t.Fatalf("bob isn't a root operator: %v", err)
	}
	ch, err := b.srv.BeginRootShell(b.sshLoginOf("alice"), "kubelet")
	if err != nil {
		t.Fatal(err)
	}
	bob := b.browser()
	bob.signIn("bob")
	_, err = rootShellClient(bob).IssueRootShellCode(ctx, connect.NewRequest(&osadminv1.IssueRootShellCodeRequest{Challenge: ch.Challenge, TotpCode: b.code("bob")}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	alice := b.browser()
	alice.signIn("alice")
	_, err = rootShellClient(alice).IssueRootShellCode(ctx, connect.NewRequest(&osadminv1.IssueRootShellCodeRequest{Challenge: ch.Challenge, TotpCode: "000000"}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_CREDENTIALS")
	out, err := rootShellClient(alice).IssueRootShellCode(ctx, connect.NewRequest(&osadminv1.IssueRootShellCodeRequest{Challenge: strings.ToLower(ch.Challenge), TotpCode: b.code("alice")}))
	if err != nil {
		t.Fatal(err)
	}
	m := out.Msg
	if len(m.GetCode()) != 9 || m.GetSourceAddress() != "192.0.2.50" || m.GetSessionMinutes() != 10 || !m.GetExpires().AsTime().Equal(b.clk.Now().UTC().Truncate(time.Second).Add(10*time.Minute)) {
		t.Fatalf("code %v", m)
	}
	if e := lastEntry(t, b.log, "rootshell.code.issue"); e.Outcome != "ok" || e.Actor != "alice" {
		t.Fatalf("audit %+v", e)
	}
	r, ticket, err := b.srv.OpenRootShell(b.sshLoginOf("alice"), ch.Challenge, m.GetCode())
	if err != nil || ticket == "" || r.State != elevation.Opened {
		t.Fatalf("open %+v %v", r, err)
	}
	if _, _, err := b.srv.OpenRootShell(b.sshLoginOf("alice"), ch.Challenge, m.GetCode()); !codes.Is(err, codes.RootChallenge) {
		t.Fatalf("the code worked twice: %v", err)
	}
}

// Wrong root-shell codes count toward the operator's lockout.
func TestWrongRootShellCodesCountTowardTheLockout(t *testing.T) {
	b := newBox(t, false)
	ch, err := b.srv.BeginRootShell(b.sshLoginOf("alice"), "")
	if err != nil {
		t.Fatal(err)
	}
	alice := b.browser()
	alice.signIn("alice")
	if _, err := rootShellClient(alice).IssueRootShellCode(context.Background(), connect.NewRequest(&osadminv1.IssueRootShellCodeRequest{Challenge: ch.Challenge, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, _, err := b.srv.OpenRootShell(b.sshLoginOf("alice"), ch.Challenge, "0000-0000"); !codes.Is(err, codes.RootCode) {
			t.Fatalf("a wrong code: %v", err)
		}
	}
	if _, err := b.srv.VerifyLoginTotp(b.sshLoginOf("alice"), "000000"); !codes.Is(err, codes.AccessCredentials) {
		t.Fatal(err)
	}
	if _, err := b.srv.VerifyLoginTotp(b.sshLoginOf("alice"), b.code("alice")); !codes.Is(err, codes.AccessLocked) {
		t.Fatalf("two wrong root codes and a wrong TOTP code lock: %v", err)
	}
}
