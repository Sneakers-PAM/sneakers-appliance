// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

func TestSignInEndToEnd(t *testing.T) {
	b := newBox(t, false)
	br := b.browser()
	si := osadminv1connect.NewSignInServiceClient(br.hc, b.ts.URL)
	ctx := context.Background()
	begin, err := si.BeginSignIn(ctx, connect.NewRequest(&osadminv1.BeginSignInRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if begin.Msg.GetUserAgent() != "TestBrowser/1.0" || begin.Msg.GetSourceAddress() != "127.0.0.1" {
		t.Fatalf("the page shows what the box sees: %v", begin.Msg)
	}
	if !begin.Msg.GetExpires().AsTime().Equal(b.clk.Now().Add(5 * time.Minute)) {
		t.Fatal("a code lasts 5 minutes")
	}
	poll, err := si.PollSignIn(ctx, connect.NewRequest(&osadminv1.PollSignInRequest{PollToken: begin.Msg.GetPollToken()}))
	if err != nil || poll.Msg.GetState() != osadminv1.SignInState_SIGN_IN_STATE_PENDING {
		t.Fatalf("pending: %v %v", poll, err)
	}
	if err := b.srv.ApproveSignIn(0, begin.Msg.GetCode(), "alice", b.keys["alice"].fp, "192.0.2.77"); err != nil {
		t.Fatal(err)
	}
	ap := lastEntry(t, b.log, "signin.approve")
	if ap.Actor != "alice" || ap.KeyFP != b.keys["alice"].fp || ap.Detail["browser"] != "127.0.0.1" || ap.Detail["userAgent"] != "TestBrowser/1.0" {
		t.Fatalf("the approval names the browser: %+v", ap)
	}
	resp, err := si.PollSignIn(ctx, connect.NewRequest(&osadminv1.PollSignInRequest{PollToken: begin.Msg.GetPollToken()}))
	if err != nil || resp.Msg.GetState() != osadminv1.SignInState_SIGN_IN_STATE_APPROVED {
		t.Fatalf("approved: %v %v", resp, err)
	}
	ck := resp.Header().Get("Set-Cookie")
	for _, want := range []string{osadmin.CookieName + "=", "Path=/", "HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(ck, want) {
			t.Errorf("cookie %q lacks %s", ck, want)
		}
	}
	if strings.Contains(strings.ToLower(ck), "domain=") {
		t.Error("the cookie must be host-only")
	}
	s := resp.Msg.GetSession()
	if s.GetAdmin() != "alice" || s.GetRole() != osadminv1.Role_ROLE_OWNER || s.GetKeyFingerprint() != b.keys["alice"].fp || s.GetCsrfToken() == "" {
		t.Fatalf("session %v", s)
	}
	br.csrf = s.GetCsrfToken()
	got, err := si.GetSession(ctx, connect.NewRequest(&osadminv1.GetSessionRequest{}))
	if err != nil || got.Msg.GetSession().GetAdmin() != "alice" {
		t.Fatalf("%v %v", got, err)
	}
	if again, _ := si.PollSignIn(ctx, connect.NewRequest(&osadminv1.PollSignInRequest{PollToken: begin.Msg.GetPollToken()})); again.Msg.GetState() != osadminv1.SignInState_SIGN_IN_STATE_EXPIRED {
		t.Fatal("a code works once")
	}
	if _, err := si.SignOut(ctx, connect.NewRequest(&osadminv1.SignOutRequest{})); err != nil {
		t.Fatal(err)
	}
	_, err = si.GetSession(ctx, connect.NewRequest(&osadminv1.GetSessionRequest{}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
}

func TestExpiredCodeCantBeApproved(t *testing.T) {
	b := newBox(t, false)
	si := osadminv1connect.NewSignInServiceClient(b.browser().hc, b.ts.URL)
	begin, err := si.BeginSignIn(context.Background(), connect.NewRequest(&osadminv1.BeginSignInRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	b.clk.Advance(5*time.Minute + time.Second)
	err = b.srv.ApproveSignIn(0, begin.Msg.GetCode(), "alice", b.keys["alice"].fp, "192.0.2.77")
	if err == nil || !strings.Contains(err.Error(), "unknown, used or expired") {
		t.Fatalf("expired code: %v", err)
	}
	if lastEntry(t, b.log, "signin.approve").Code != "LOGIN_CODE" {
		t.Fatal("refusal audited")
	}
}

func TestApprovalNeedsTheAdminsOwnKeyAndUID(t *testing.T) {
	b := newBox(t, true)
	si := osadminv1connect.NewSignInServiceClient(b.browser().hc, b.ts.URL)
	begin, _ := si.BeginSignIn(context.Background(), connect.NewRequest(&osadminv1.BeginSignInRequest{}))
	code := begin.Msg.GetCode()
	if err := b.srv.ApproveSignIn(0, code, "alice", b.keys["bob"].fp, "192.0.2.77"); err == nil {
		t.Fatal("bob's key can't approve as alice")
	}
	if err := b.srv.ApproveSignIn(20001, code, "alice", b.keys["alice"].fp, "192.0.2.77"); err == nil {
		t.Fatal("bob's uid can't approve as alice")
	}
	if err := b.srv.ApproveSignIn(20000, code, "alice", b.keys["alice"].fp, "192.0.2.77"); err != nil {
		t.Fatalf("alice's own uid: %v", err)
	}
}

func TestCallsNeedASession(t *testing.T) {
	b := newBox(t, false)
	_, err := b.browser().access().ListAdmins(context.Background(), connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
}

func TestCSRF(t *testing.T) {
	b := newBox(t, false)
	br := b.browser()
	br.signIn("alice")
	token := br.csrf
	br.csrf = ""
	ctx := context.Background()
	if _, err := br.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{})); err != nil {
		t.Fatalf("a read needs no CSRF token: %v", err)
	}
	k := newKey(t)
	_, err := br.access().AddKey(ctx, connect.NewRequest(&osadminv1.AddKeyRequest{Admin: "alice", PublicKey: k.line}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	if e := lastEntry(t, b.log, "access.key.add"); e.Outcome != "refused" || e.Code != "ACCESS_FORBIDDEN" {
		t.Fatalf("refusal audited: %+v", e)
	}
	br.csrf = "wrong"
	_, err = br.access().AddKey(ctx, connect.NewRequest(&osadminv1.AddKeyRequest{Admin: "alice", PublicKey: k.line}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	br.csrf = token
	if _, err := br.access().AddKey(ctx, connect.NewRequest(&osadminv1.AddKeyRequest{Admin: "alice", PublicKey: k.line})); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, b.log, "access.key.add"); e.Outcome != "ok" || e.Actor != "alice" || e.Target != "alice" || e.Detail["key"] != k.fp {
		t.Fatalf("audited: %+v", e)
	}
}

func TestStepUp(t *testing.T) {
	b := newBox(t, false)
	br := b.browser()
	first := br.signIn("alice")
	b.clk.Advance(6 * time.Minute)
	ctx := context.Background()
	k := newKey(t)
	_, err := br.access().AddKey(ctx, connect.NewRequest(&osadminv1.AddKeyRequest{Admin: "alice", PublicKey: k.line}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_STEPUP_REQUIRED")
	if _, err := br.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{})); err != nil {
		t.Fatalf("reads need no step-up: %v", err)
	}
	second := br.signIn("alice")
	if second.GetCsrfToken() == first.GetCsrfToken() {
		t.Fatal("the step-up is a new session")
	}
	if n := len(b.srv.Sessions().Of("alice")); n != 1 {
		t.Fatalf("the step-up replaces the old session: %d", n)
	}
	if _, err := br.access().AddKey(ctx, connect.NewRequest(&osadminv1.AddKeyRequest{Admin: "alice", PublicKey: k.line})); err != nil {
		t.Fatal(err)
	}
}

func TestIdleTimeout(t *testing.T) {
	b := newBox(t, false)
	br := b.browser()
	br.signIn("alice")
	b.clk.Advance(weblogin.IdleTimeout + time.Second)
	_, err := br.access().ListAdmins(context.Background(), connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
}

func TestAtMostFiveSessionsPerAdmin(t *testing.T) {
	b := newBox(t, false)
	first := b.browser()
	first.signIn("alice")
	for range 5 {
		b.clk.Advance(time.Second)
		b.browser().signIn("alice")
	}
	_, err := first.access().ListAdmins(context.Background(), connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
	if n := len(b.srv.Sessions().Of("alice")); n != 5 {
		t.Fatalf("%d sessions", n)
	}
}

func TestEveryMethodHasARule(t *testing.T) {
	files := 0
	protoregistry.GlobalFiles.RangeFilesByPackage("sneakers.appliance.osadmin.v1", func(fd protoreflect.FileDescriptor) bool {
		files++
		svcs := fd.Services()
		for i := range svcs.Len() {
			svc := svcs.Get(i)
			if svc.Name() == "LocalService" {
				continue
			}
			ms := svc.Methods()
			for j := range ms.Len() {
				m := ms.Get(j)
				r := osadmin.RuleOf(m)
				if r == nil {
					t.Errorf("%s has no rule", m.FullName())
					continue
				}
				if r.GetPublic() {
					if svc.Name() != "SignInService" && m.FullName() != "sneakers.appliance.osadmin.v1.SetupService.RedeemCode" {
						t.Errorf("%s is public", m.FullName())
					}
					continue
				}
				if r.GetRole() == osadminv1.Role_ROLE_UNSPECIFIED && !r.GetCodeSession() {
					t.Errorf("%s has no role", m.FullName())
				}
				opts, _ := m.Options().(*descriptorpb.MethodOptions)
				read := opts.GetIdempotencyLevel() == descriptorpb.MethodOptions_NO_SIDE_EFFECTS
				if !read && !strings.HasSuffix(string(m.Name()), "Session") && !strings.HasPrefix(string(m.Name()), "Get") && !strings.HasPrefix(string(m.Name()), "List") && m.Name() != "RunChecks" && r.GetAudit() == "" {
					t.Errorf("%s changes something and names no audit action", m.FullName())
				}
			}
		}
		return true
	})
	if files < 13 {
		t.Fatalf("only %d osadmin files registered", files)
	}
}

func TestServicesWithoutABackendAreNotAvailable(t *testing.T) {
	b := newBox(t, false)
	br := b.browser()
	br.signIn("alice")
	_, err := osadminv1connect.NewTlsServiceClient(br.hc, b.ts.URL).GetTls(context.Background(), connect.NewRequest(&osadminv1.GetTlsRequest{}))
	if connect.CodeOf(err) != connect.CodeUnimplemented || !strings.Contains(err.Error(), osadmin.NotAvailable) {
		t.Fatalf("got %v", err)
	}
	_, err = osadminv1connect.NewTlsServiceClient(b.browser().hc, b.ts.URL).GetTls(context.Background(), connect.NewRequest(&osadminv1.GetTlsRequest{}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
}

func TestSecurityHeaders(t *testing.T) {
	b := newBox(t, false)
	resp, err := b.ts.Client().Get(b.ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("headers %v", resp.Header)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.Status)
	}
}
