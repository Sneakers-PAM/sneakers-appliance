// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accounts"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

func TestThePeerRule(t *testing.T) {
	for _, c := range []struct {
		uid  uint32
		want bool
	}{{0, true}, {accounts.OsadminUID, true}, {accounts.EdgefallUID, true}, {20000, true}, {20001, true}, {100, false}, {101, false}, {1000, false}, {65534, false}} {
		if got := accessd.PeerAllowed(c.uid); got != c.want {
			t.Errorf("uid %d: %v", c.uid, got)
		}
	}
}

// sneakers-edgefall's uid asks the public GetPhase and nothing else: not
// the rest of the front's API, not the local services.
func TestTheEdgeFallbackOnlyAsksThePhase(t *testing.T) {
	b := newBox(t)
	hc, url := b.as(accounts.EdgefallUID)
	ctx := context.Background()
	st := osadminv1connect.NewStatusServiceClient(hc, url)
	if p, err := st.GetPhase(ctx, connect.NewRequest(&osadminv1.GetPhaseRequest{})); err != nil || p.Msg.GetState() == "" {
		t.Fatalf("GetPhase: %v %v", p, err)
	}
	if _, err := st.GetStatus(ctx, connect.NewRequest(&osadminv1.GetStatusRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("GetStatus: %v", err)
	}
	if _, err := osadminv1connect.NewSignInServiceClient(hc, url).GetSession(ctx, connect.NewRequest(&osadminv1.GetSessionRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("GetSession: %v", err)
	}
	if _, err := accessv1connect.NewAccessServiceClient(hc, url).GetStatus(ctx, connect.NewRequest(&accessv1.GetStatusRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("access GetStatus: %v", err)
	}
}

// Root is the console: every method, as an owner named console.
func TestRootGetsTheFullServices(t *testing.T) {
	b := newBox(t)
	hc, url := b.console()
	ctx := context.Background()
	if _, err := accessv1connect.NewAccessServiceClient(hc, url).AddAdmin(ctx, connect.NewRequest(&accessv1.AddAdminRequest{Name: "carol", Role: osadminv1.Role_ROLE_ADMIN})); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, b.log, "access.admin.add"); e.Actor != "console" || e.Detail["surface"] != "console" || e.Outcome != "ok" {
		t.Fatalf("%+v", e)
	}
	res, err := accessv1connect.NewNetworkServiceClient(hc, url).ResetAllowList(ctx, connect.NewRequest(&accessv1.ResetAllowListRequest{}))
	if err != nil || res.Msg.GetToken() == "" {
		t.Fatalf("%v %v", res, err)
	}
	if got := b.netd.allowList(); !slices.Equal(got, []string{"192.0.2.0/24", "2001:db8::/64"}) {
		t.Fatalf("allow-list %v", got)
	}
}

// An admin uid is that admin, with that admin's role: bob (an admin) sees
// his own keys, can't see alice's, and can't add an admin; alice (an
// owner) can.
func TestAnAdminUIDActsAsThatAdmin(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	bob := b.shell("bob")
	keys, err := bob.ListKeys(ctx, connect.NewRequest(&accessv1.ListKeysRequest{}))
	if err != nil || keys.Msg.GetAdmin() != "bob" || len(keys.Msg.GetKeys()) != 1 || keys.Msg.GetKeys()[0].GetFingerprint() != b.keys["bob"].fp {
		t.Fatalf("%v %v", keys, err)
	}
	_, err = bob.ListKeys(ctx, connect.NewRequest(&accessv1.ListKeysRequest{Admin: "alice"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	_, err = bob.AddAdmin(ctx, connect.NewRequest(&accessv1.AddAdminRequest{Name: "carol", Role: osadminv1.Role_ROLE_ADMIN}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	if e := lastEntry(t, b.log, "access.admin.add"); e.Actor != "bob" || e.Outcome != "refused" || e.Detail["surface"] != "ssh" || e.Source != "192.0.2.50" || e.KeyFP != b.keys["bob"].fp {
		t.Fatalf("%+v", e)
	}
	if _, err := b.shell("alice").AddAdmin(ctx, connect.NewRequest(&accessv1.AddAdminRequest{Name: "carol", Role: osadminv1.Role_ROLE_ADMIN})); err != nil {
		t.Fatal(err)
	}
	st := b.store.Read()
	if a, ok := st.Admin("carol"); !ok || a.CreatedBy != "alice" {
		t.Fatalf("%+v %v", a, ok)
	}
	if a, _ := st.Admin("carol"); a.Invite == nil {
		t.Fatal("carol has no invitation")
	}
}

// The fingerprint a shell sends must be one of its own admin's keys; the
// uid is the identity, not anything in the request.
func TestAnAdminUIDCantClaimAnotherAdminsKey(t *testing.T) {
	b := newBox(t)
	hc, url := b.as(b.uids["bob"])
	c := accessv1connect.NewAccessServiceClient(hc, url, connect.WithInterceptors(keyHeader(b.keys["alice"].fp)))
	_, err := c.ListAdmins(context.Background(), connect.NewRequest(&accessv1.ListAdminsRequest{}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}

// The console's methods stay the console's, even for an owner's shell.
func TestAnAdminUIDCantCallARootOnlyMethod(t *testing.T) {
	b := newBox(t)
	hc, url := b.as(b.uids["alice"])
	ctx := context.Background()
	opt := connect.WithInterceptors(keyHeader(b.keys["alice"].fp))
	_, err := accessv1connect.NewNetworkServiceClient(hc, url, opt).ResetAllowList(ctx, connect.NewRequest(&accessv1.ResetAllowListRequest{}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	_, err = accessv1connect.NewSetupServiceClient(hc, url, opt).Complete(ctx, connect.NewRequest(&accessv1.CompleteRequest{}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	_, err = accessv1connect.NewAccessServiceClient(hc, url, opt).AddRecoveryKey(ctx, connect.NewRequest(&accessv1.AddRecoveryKeyRequest{PublicKey: newKey(t).line}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	if got := b.netd.allowList(); !slices.Equal(got, []string{"198.51.100.0/24"}) {
		t.Fatalf("allow-list changed: %v", got)
	}
}

// A uid in the admin range with no admin behind it gets nothing.
func TestAnUnknownAdminUIDIsRefused(t *testing.T) {
	b := newBox(t)
	hc, url := b.as(20099)
	_, err := accessv1connect.NewAccessServiceClient(hc, url).ListAdmins(context.Background(), connect.NewRequest(&accessv1.ListAdminsRequest{}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}

// The admin uids don't get the :8443 API, and the osadmin uid doesn't get
// the local API.
func TestEachPeerClassGetsOnlyItsServices(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	hc, url := b.as(b.uids["alice"])
	if _, err := osadminv1connect.NewAccessServiceClient(hc, url).ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("an admin uid reached the :8443 API: %v", err)
	}
	if _, err := accessv1connect.NewBindingServiceClient(hc, url).GetBinding(ctx, connect.NewRequest(&accessv1.GetBindingRequest{})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("an admin uid got the binding: %v", err)
	}
	ohc, ourl := b.osadmin()
	if _, err := accessv1connect.NewAccessServiceClient(ohc, ourl).ListAdmins(ctx, connect.NewRequest(&accessv1.ListAdminsRequest{})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("osadmin reached the local API: %v", err)
	}
	if _, err := osadminv1connect.NewLocalServiceClient(ohc, ourl).ApproveSignIn(ctx, connect.NewRequest(&osadminv1.ApproveSignInRequest{Code: "X", Admin: "alice"})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("osadmin reached LocalService: %v", err)
	}
	bind, err := accessv1connect.NewBindingServiceClient(ohc, ourl).GetBinding(ctx, connect.NewRequest(&accessv1.GetBindingRequest{}))
	if err != nil || bind.Msg.GetHostname() != "box1.sneakers.example.org" || !slices.Equal(bind.Msg.GetManagementAddresses(), []string{"192.0.2.10", "2001:db8::10"}) {
		t.Fatalf("%v %v", bind, err)
	}
}

// The osadmin uid's calls each carry the signed-in admin's session, and
// accessd checks it: without one nothing happens.
func TestAnOsadminCallWithoutASessionIsRefused(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	_, err := b.osadminAccess().AddAdmin(ctx, connect.NewRequest(&osadminv1.AddAdminRequest{Name: "carol", Role: osadminv1.Role_ROLE_ADMIN}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
	hc, url := b.osadmin()
	req := connect.NewRequest(&osadminv1.ListAdminsRequest{})
	req.Header().Set("Cookie", osadmin.CookieName+"=forged")
	_, err = osadminv1connect.NewAccessServiceClient(hc, url).ListAdmins(ctx, req)
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
	st := b.store.Read()
	if _, ok := st.Admin("carol"); ok {
		t.Fatal("an unauthenticated call changed the store")
	}
}

// The whole :8443 sign-in through accessd: the browser's address is the
// one sneakers-osadmin forwards, and the session's role is checked in
// accessd.
func TestAnOsadminCallWithASession(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	cookie, csrf := b.signIn("bob")
	if e := lastEntry(t, b.log, "signin.password"); e.Source != "203.0.113.9" || e.Outcome != "ok" {
		t.Fatalf("audit %+v", e)
	}
	if _, err := b.osadminAccess().ListAdmins(ctx, withSession(connect.NewRequest(&osadminv1.ListAdminsRequest{}), cookie, csrf)); err != nil {
		t.Fatal(err)
	}
	_, err := b.osadminAccess().AddAdmin(ctx, withSession(connect.NewRequest(&osadminv1.AddAdminRequest{Name: "carol", Role: osadminv1.Role_ROLE_ADMIN}), cookie, csrf))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}

// The closed shell's TOTP check over access.sock: the issued key sshd
// named, a fresh code, under the lockout.
func TestTheClosedShellsTOTPCheck(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	hc, url := b.as(b.uids["bob"])
	login := accessv1connect.NewSshLoginServiceClient(hc, url, connect.WithInterceptors(keyHeader(b.keys["bob"].fp)))
	if _, err := login.VerifyTotp(ctx, connect.NewRequest(&accessv1.VerifyTotpRequest{TotpCode: "000000"})); err == nil || !strings.Contains(err.Error(), "ACCESS_CREDENTIALS") {
		t.Fatalf("a wrong code: %v", err)
	}
	out, err := login.VerifyTotp(ctx, connect.NewRequest(&accessv1.VerifyTotpRequest{TotpCode: b.code("bob")}))
	if err != nil || out.Msg.GetAdmin() != "bob" || out.Msg.GetLoginId() == "" {
		t.Fatalf("%v %v", out, err)
	}
	if _, err := login.EndSshLogin(ctx, connect.NewRequest(&accessv1.EndSshLoginRequest{LoginId: out.Msg.GetLoginId()})); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, b.log, "ssh.logout"); e.Actor != "bob" || e.Target != "bob's SSH login from 192.0.2.50" || e.Detail["login"] != out.Msg.GetLoginId() {
		t.Fatalf("audit %+v", e)
	}
	other := accessv1connect.NewSshLoginServiceClient(hc, url, connect.WithInterceptors(keyHeader(b.keys["alice"].fp)))
	if _, err := other.VerifyTotp(ctx, connect.NewRequest(&accessv1.VerifyTotpRequest{TotpCode: b.code("bob")})); err == nil {
		t.Fatal("bob's login passed with alice's key")
	}
	_, err = accessv1connect.NewSshLoginServiceClient(b.console()).VerifyTotp(ctx, connect.NewRequest(&accessv1.VerifyTotpRequest{TotpCode: "123456"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}

// The console reads its info and is woken by every change.
func TestTheConsoleInfoStream(t *testing.T) {
	b := newBox(t)
	hc, url := b.console()
	su := accessv1connect.NewSetupServiceClient(hc, url)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got, err := su.GetConsoleInfo(ctx, connect.NewRequest(&accessv1.GetConsoleInfoRequest{}))
	if err != nil || got.Msg.GetConsoleInfo().GetUrl() != "https://192.0.2.10:8443" || got.Msg.GetConsoleInfo().GetFqdn() != "box1.sneakers.example.org" {
		t.Fatalf("%v %v", got, err)
	}
	stream, err := su.WatchConsoleInfo(ctx, connect.NewRequest(&accessv1.WatchConsoleInfoRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() || stream.Msg().GetConsoleInfo().GetRecover() != nil {
		t.Fatalf("first send: %v", stream.Err())
	}
	rec, err := su.BeginRecoverAccess(ctx, connect.NewRequest(&accessv1.BeginRecoverAccessRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() || stream.Msg().GetConsoleInfo().GetRecover().GetCode() != rec.Msg.GetRecover().GetCode() {
		t.Fatalf("the change didn't reach the stream: %v", stream.Err())
	}
	shc, surl := b.as(b.uids["alice"])
	_, err = accessv1connect.NewSetupServiceClient(shc, surl, connect.WithInterceptors(keyHeader(b.keys["alice"].fp))).GetConsoleInfo(ctx, connect.NewRequest(&accessv1.GetConsoleInfoRequest{}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}

// Every status accessd computes is kept in /run for when it's down.
func TestStatusIsCachedForWhenAccessdIsDown(t *testing.T) {
	b := newBox(t)
	res, err := b.shell("bob").GetStatus(context.Background(), connect.NewRequest(&accessv1.GetStatusRequest{}))
	if err != nil || res.Msg.GetStatus().GetHostname() != "box1.sneakers.example.org" {
		t.Fatalf("%v %v", res, err)
	}
	raw, err := os.ReadFile(filepath.Join(b.run, "access", "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cached map[string]any
	if err := json.Unmarshal(raw, &cached); err != nil {
		t.Fatal(err)
	}
	st, err := accessapi.ReadStatusCache(filepath.Join(b.run, "access", "status.json"))
	if err != nil || st.Status.GetHostname() != "box1.sneakers.example.org" || st.Saved.IsZero() {
		t.Fatalf("%+v %v", st, err)
	}
	fi, err := os.Stat(filepath.Join(b.run, "access", "status.json"))
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("%v %v", fi, err)
	}
}
