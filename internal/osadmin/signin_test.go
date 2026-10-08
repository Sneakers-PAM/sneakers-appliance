// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"errors"
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
	"github.com/Sneakers-PAM/sneakers-appliance/internal/credentials"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

func signInClient(br *browser) osadminv1connect.SignInServiceClient {
	return osadminv1connect.NewSignInServiceClient(br.hc, br.b.ts.URL)
}

func trySignIn(br *browser, admin, password, code string) (*connect.Response[osadminv1.SignInResponse], error) {
	return signInClient(br).SignIn(context.Background(), connect.NewRequest(&osadminv1.SignInRequest{Admin: admin, Password: password, TotpCode: code}))
}

// refusalOf is the SignInRefusal detail of a refused call.
func refusalOf(t *testing.T, err error) *osadminv1.SignInRefusal {
	t.Helper()
	ce := new(connect.Error)
	if !errors.As(err, &ce) {
		t.Fatalf("not a connect error: %v", err)
	}
	for _, d := range ce.Details() {
		v, derr := d.Value()
		if r, ok := v.(*osadminv1.SignInRefusal); derr == nil && ok {
			return r
		}
	}
	t.Fatalf("no SignInRefusal detail on %v", err)
	return nil
}

func TestSignInEndToEnd(t *testing.T) {
	b := newBox(t, false)
	br := b.browser()
	resp, err := trySignIn(br, "alice", testPassword, b.code("alice"))
	if err != nil {
		t.Fatal(err)
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
	if s.GetAdmin() != "alice" || s.GetRole() != osadminv1.Role_ROLE_OWNER || s.GetCsrfToken() == "" || !s.GetRootOperator() {
		t.Fatalf("session %v", s)
	}
	if e := lastEntry(t, b.log, "signin.password"); e.Outcome != "ok" || e.Target != "alice" {
		t.Fatalf("the sign-in is audited: %+v", e)
	}
	br.csrf = s.GetCsrfToken()
	si := signInClient(br)
	ctx := context.Background()
	got, err := si.GetSession(ctx, connect.NewRequest(&osadminv1.GetSessionRequest{}))
	if err != nil || got.Msg.GetSession().GetAdmin() != "alice" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := si.SignOut(ctx, connect.NewRequest(&osadminv1.SignOutRequest{})); err != nil {
		t.Fatal(err)
	}
	_, err = si.GetSession(ctx, connect.NewRequest(&osadminv1.GetSessionRequest{}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
}

// The sign-in code approved over SSH is gone.
func TestTheSSHSignInCodeIsGone(t *testing.T) {
	b := newBox(t, false)
	_, err := signInClient(b.browser()).BeginSignIn(context.Background(), connect.NewRequest(&osadminv1.BeginSignInRequest{})) //nolint:staticcheck // the deprecated RPC is gone
	if connect.CodeOf(err) != connect.CodeUnimplemented || !strings.Contains(err.Error(), osadmin.NotAvailable) {
		t.Fatalf("BeginSignIn: %v", err)
	}
}

// A wrong name, a wrong password and a wrong or reused code get the same
// answer, so the page can't tell which.
func TestEveryWrongSignInLooksTheSame(t *testing.T) {
	b := newBox(t, true)
	br := b.browser()
	code := b.code("alice")
	if _, err := trySignIn(br, "alice", testPassword, code); err != nil {
		t.Fatal(err)
	}
	for name, try := range map[string][3]string{
		"unknown name":   {"zed", testPassword, code},
		"wrong password": {"bob", testPassword + "x", credentials.TOTP(b.totp["bob"], b.clk.Now())},
		"wrong code":     {"bob", testPassword, "000000"},
		"reused code":    {"alice", testPassword, code},
	} {
		_, err := trySignIn(br, try[0], try[1], try[2])
		symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_CREDENTIALS")
		if !strings.Contains(err.Error(), "check the name, the password and the authenticator code") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Three failures within 15 minutes lock the account for 15 minutes, even
// with the right password and code, and the lock is audited (NIST SP
// 800-53 AC-7).
func TestThreeFailedSignInsLockForFifteenMinutes(t *testing.T) {
	b := newBox(t, false)
	br := b.browser()
	for i, left := range []int32{2, 1} {
		_, err := trySignIn(br, "alice", "not the password", b.code("alice"))
		if r := refusalOf(t, err); r.GetAttemptsLeft() != left {
			t.Fatalf("try %d: %v", i, r)
		}
		b.clk.Advance(5 * time.Minute)
	}
	_, err := trySignIn(br, "alice", "not the password", b.code("alice"))
	r := refusalOf(t, err)
	if r.GetAttemptsLeft() != 0 || !r.GetLockedUntil().AsTime().Equal(b.clk.Now().Add(15*time.Minute)) {
		t.Fatalf("the third failure: %v", r)
	}
	if e := lastEntry(t, b.log, "access.lockout"); e.Target != "alice" || e.Detail["until"] == "" {
		t.Fatalf("the lock isn't audited: %+v", e)
	}
	_, err = trySignIn(br, "alice", testPassword, b.code("alice"))
	symbolIn(t, err, connect.CodeResourceExhausted, "ACCESS_LOCKED")
	b.clk.Advance(15 * time.Minute)
	if _, err := trySignIn(br, "alice", testPassword, b.code("alice")); err != nil {
		t.Fatalf("the lock should be over: %v", err)
	}
}

func TestFailuresSpreadOverMoreThanFifteenMinutesDontLock(t *testing.T) {
	b := newBox(t, false)
	br := b.browser()
	for range 3 {
		_, _ = trySignIn(br, "alice", "not the password", b.code("alice"))
		b.clk.Advance(8 * time.Minute)
	}
	if _, err := trySignIn(br, "alice", testPassword, b.code("alice")); err != nil {
		t.Fatalf("locked by failures 16 minutes apart: %v", err)
	}
}

func TestASuccessResetsTheCount(t *testing.T) {
	b := newBox(t, false)
	br := b.browser()
	for range 2 {
		_, _ = trySignIn(br, "alice", "not the password", b.code("alice"))
	}
	if _, err := trySignIn(br, "alice", testPassword, b.code("alice")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		_, _ = trySignIn(br, "alice", "not the password", b.code("alice"))
	}
	if _, err := trySignIn(br, "alice", testPassword, b.code("alice")); err != nil {
		t.Fatalf("a success didn't reset the count: %v", err)
	}
}

// The owner's other lockout mode holds the lock until an owner unlocks it,
// and the unlock is audited.
func TestTheLockCanWaitForAnOwner(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	if _, err := alice.access().SetAccessPolicy(ctx, connect.NewRequest(&osadminv1.SetAccessPolicyRequest{Policy: &osadminv1.AccessPolicy{
		LockoutMode: osadminv1.LockoutMode_LOCKOUT_MODE_UNTIL_UNLOCKED, RootCodeMinutes: 10, RootSessionMinutes: 10, SshKeyValidDays: 365,
	}})); err != nil {
		t.Fatal(err)
	}
	bob := b.browser()
	for range 3 {
		_, _ = trySignIn(bob, "bob", "not the password", b.code("bob"))
	}
	b.clk.Advance(48 * time.Hour)
	_, err := trySignIn(bob, "bob", testPassword, b.code("bob"))
	symbolIn(t, err, connect.CodeResourceExhausted, "ACCESS_LOCKED")
	if !refusalOf(t, err).GetLockedUntilUnlocked() {
		t.Fatal("the refusal doesn't say an owner must unlock")
	}
	alice.signIn("alice")
	list, err := alice.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range list.Msg.GetAdmins() {
		if a.GetName() == "bob" && !a.GetLockedUntilUnlocked() {
			t.Fatalf("the Access page doesn't show the lock: %v", a)
		}
	}
	if _, err := alice.access().UnlockAdmin(ctx, connect.NewRequest(&osadminv1.UnlockAdminRequest{Name: "bob"})); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, b.log, "access.admin.unlock"); e.Outcome != "ok" || e.Target != "bob" || e.Detail["wasLocked"] != "true" {
		t.Fatalf("the unlock isn't audited: %+v", e)
	}
	if _, err := trySignIn(bob, "bob", testPassword, b.code("bob")); err != nil {
		t.Fatalf("after the unlock: %v", err)
	}
}

// One address that keeps failing is held off whatever names it tries
// (NIST SP 800-63B), and the throttle is audited.
func TestOneSourceIsThrottled(t *testing.T) {
	b := newBox(t, false)
	br := b.browser()
	for i := range 10 {
		_, _ = trySignIn(br, "nobody"+strings.Repeat("x", i), "guess", "000000")
	}
	_, err := trySignIn(br, "alice", testPassword, b.code("alice"))
	symbolIn(t, err, connect.CodeResourceExhausted, "ACCESS_THROTTLED")
	if refusalOf(t, err).GetRetryAfter() == nil {
		t.Fatal("no retry time")
	}
	if e := lastEntry(t, b.log, "access.throttle"); e.Source != "127.0.0.1" {
		t.Fatalf("the throttle isn't audited: %+v", e)
	}
	b.clk.Advance(15 * time.Minute)
	if _, err := trySignIn(br, "alice", testPassword, b.code("alice")); err != nil {
		t.Fatalf("after the hold: %v", err)
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
	_, err := br.access().IssueSshKey(ctx, connect.NewRequest(&osadminv1.IssueSshKeyRequest{Label: "laptop"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	if e := lastEntry(t, b.log, "access.ssh-key.issue"); e.Outcome != "refused" || e.Code != "ACCESS_FORBIDDEN" {
		t.Fatalf("refusal audited: %+v", e)
	}
	br.csrf = "wrong"
	_, err = br.access().IssueSshKey(ctx, connect.NewRequest(&osadminv1.IssueSshKeyRequest{Label: "laptop"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	br.csrf = token
	if _, err := br.access().IssueSshKey(ctx, connect.NewRequest(&osadminv1.IssueSshKeyRequest{Label: "laptop", TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, b.log, "access.ssh-key.issue"); e.Outcome != "ok" || e.Actor != "alice" || e.Target != "alice" {
		t.Fatalf("audited: %+v", e)
	}
}

// After 5 minutes a sensitive action asks for a fresh TOTP code; one used
// already doesn't count.
func TestStepUpTakesAFreshCode(t *testing.T) {
	b := newBox(t, false)
	br := b.browser()
	br.signIn("alice")
	b.clk.Advance(6 * time.Minute)
	ctx := context.Background()
	_, err := br.access().AddAdmin(ctx, connect.NewRequest(&osadminv1.AddAdminRequest{Name: "carol", Role: osadminv1.Role_ROLE_ADMIN}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_STEPUP_REQUIRED")
	if _, err := br.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{})); err != nil {
		t.Fatalf("reads need no step-up: %v", err)
	}
	code := b.code("alice")
	up, err := signInClient(br).StepUp(ctx, connect.NewRequest(&osadminv1.StepUpRequest{TotpCode: code}))
	if err != nil || !up.Msg.GetSession().GetStepUpUntil().AsTime().Equal(b.clk.Now().Add(5*time.Minute)) {
		t.Fatalf("step-up: %v %v", up, err)
	}
	_, err = signInClient(br).StepUp(ctx, connect.NewRequest(&osadminv1.StepUpRequest{TotpCode: code}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_CREDENTIALS")
	if _, err := br.access().AddAdmin(ctx, connect.NewRequest(&osadminv1.AddAdminRequest{Name: "carol", Role: osadminv1.Role_ROLE_ADMIN})); err != nil {
		t.Fatal(err)
	}
	if n := len(b.srv.Sessions().Of("alice")); n != 1 {
		t.Fatalf("a step-up made a second session: %d", n)
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
					if svc.Name() != "SignInService" && m.FullName() != "sneakers.appliance.osadmin.v1.SetupService.RedeemCode" && m.FullName() != "sneakers.appliance.osadmin.v1.StatusService.GetPhase" {
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
