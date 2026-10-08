// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"encoding/base32"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/credentials"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/onetime"
)

func setupClient(br *browser) osadminv1connect.SetupServiceClient {
	return osadminv1connect.NewSetupServiceClient(br.hc, br.b.ts.URL)
}

func (b *box) console() *accessv1.ConsoleInfo {
	return b.srv.ConsoleInfo(context.Background(), []string{"192.0.2.10"}, "box1.sneakers.example.org")
}

func decodeSecret(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rosterOf(names ...string) func(*access.State) error {
	return func(st *access.State) error {
		st.Quorum = &access.QuorumRoster{Members: names, Required: min(2, len(names))}
		return nil
	}
}

// enrol redeems code and sets name's password and a new authenticator,
// as the setup, invitation and Recover access pages do. It returns the
// TOTP secret.
func (br *browser) enrol(t *testing.T, code, name, password string) []byte {
	t.Helper()
	ctx := context.Background()
	su := setupClient(br)
	red, err := su.RedeemCode(ctx, connect.NewRequest(&osadminv1.RedeemCodeRequest{Code: code}))
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	br.csrf = red.Msg.GetCsrfToken()
	begin, err := su.BeginCredentials(ctx, connect.NewRequest(&osadminv1.BeginCredentialsRequest{Admin: name, Password: password}))
	if err != nil {
		t.Fatalf("begin credentials: %v", err)
	}
	secret := decodeSecret(t, begin.Msg.GetTotp().GetSecret())
	done, err := su.CompleteCredentials(ctx, connect.NewRequest(&osadminv1.CompleteCredentialsRequest{EnrolmentId: begin.Msg.GetTotp().GetId(), TotpCode: credentials.TOTP(secret, br.b.clk.Now())}))
	if err != nil {
		t.Fatalf("complete credentials: %v", err)
	}
	br.csrf = done.Msg.GetSession().GetCsrfToken()
	return secret
}

// The whole stepper on a fresh box: the console's code, the first admin
// with a password and a mandatory TOTP secret, sshd started, then the
// recovery key, the network, the protection, one sign-in and Finish. Each
// step refuses to run early.
func TestTheStepperMakesTheFirstAdmin(t *testing.T) {
	b := newFreshBox(t)
	ctx := context.Background()
	info := b.console()
	if info.GetState() != accessv1.SetupState_SETUP_STATE_NOT_STARTED || len(info.GetSetupCode()) != 19 || info.GetAttemptsLeft() != 5 ||
		info.GetUrl() != "https://192.0.2.10:8443" || info.GetFqdn() != "box1.sneakers.example.org" || info.GetSshOn() {
		t.Fatalf("console info %v", info)
	}
	if !info.GetCodeExpires().AsTime().Equal(b.clk.Now().Add(60 * time.Minute)) {
		t.Fatalf("the code works until %v", info.GetCodeExpires().AsTime())
	}
	br := b.browser()
	su := setupClient(br)
	_, err := su.BeginCredentials(ctx, connect.NewRequest(&osadminv1.BeginCredentialsRequest{Admin: "alice", Password: testPassword}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
	_, err = su.RedeemCode(ctx, connect.NewRequest(&osadminv1.RedeemCodeRequest{Code: "0000-0000"}))
	symbolIn(t, err, connect.CodeNotFound, "SETUP_CODE")
	if r := refusalOf(t, err); r.GetAttemptsLeft() != 4 {
		t.Fatalf("refusal %v", r)
	}
	red, err := su.RedeemCode(ctx, connect.NewRequest(&osadminv1.RedeemCodeRequest{Code: strings.ToLower(strings.ReplaceAll(info.GetSetupCode(), "-", " "))}))
	if err != nil || red.Msg.GetKind() != osadminv1.CodeKind_CODE_KIND_SETUP || red.Msg.GetCsrfToken() == "" {
		t.Fatalf("redeem: %v %v", red, err)
	}
	if e := lastEntry(t, b.log, "setup.code.redeem"); e.Outcome != "ok" || e.Actor != "setup" {
		t.Fatalf("audit %+v", e)
	}
	br.csrf = red.Msg.GetCsrfToken()
	if c := b.console(); c.GetState() != accessv1.SetupState_SETUP_STATE_IN_PROGRESS || c.GetSetupSource() != "127.0.0.1" || c.GetSetupCode() != "" || c.GetSetupStep() != 2 {
		t.Fatalf("console while setting up %v", c)
	}
	g, err := su.GetSetup(ctx, connect.NewRequest(&osadminv1.GetSetupRequest{}))
	if err != nil || g.Msg.GetCurrent() != 2 || len(g.Msg.GetSteps()) != 6 || g.Msg.GetCodeKind() != osadminv1.CodeKind_CODE_KIND_SETUP || len(g.Msg.GetRecoveryKeys()) != 0 {
		t.Fatalf("setup %v %v", g, err)
	}
	for pw, why := range map[string]string{"short": "too short", "password1234": "breached"} {
		c, err := su.CheckPassword(ctx, connect.NewRequest(&osadminv1.CheckPasswordRequest{Password: pw}))
		if err != nil || c.Msg.GetOk() || (why == "too short") != c.Msg.GetTooShort() || (why == "breached") != c.Msg.GetBreached() {
			t.Errorf("%s: %v %v", pw, c, err)
		}
	}
	_, err = su.BeginCredentials(ctx, connect.NewRequest(&osadminv1.BeginCredentialsRequest{Admin: "Root", Password: testPassword}))
	symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_NAME")
	_, err = su.BeginCredentials(ctx, connect.NewRequest(&osadminv1.BeginCredentialsRequest{Admin: "alice", Password: "short"}))
	symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_PASSWORD")
	begin, err := su.BeginCredentials(ctx, connect.NewRequest(&osadminv1.BeginCredentialsRequest{Admin: "alice", Password: testPassword}))
	if err != nil {
		t.Fatal(err)
	}
	tw := begin.Msg.GetTotp()
	if tw.GetDigits() != 6 || tw.GetPeriodSeconds() != 30 || !strings.HasPrefix(tw.GetUri(), "otpauth://totp/box1.sneakers.example.org:alice?") {
		t.Fatalf("totp %v", tw)
	}
	if len(b.store.Read().Admins) != 0 {
		t.Fatal("an admin was stored before the TOTP check")
	}
	secret := decodeSecret(t, tw.GetSecret())
	_, err = su.CompleteCredentials(ctx, connect.NewRequest(&osadminv1.CompleteCredentialsRequest{EnrolmentId: tw.GetId(), TotpCode: "000000"}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_CREDENTIALS")
	done, err := su.CompleteCredentials(ctx, connect.NewRequest(&osadminv1.CompleteCredentialsRequest{EnrolmentId: tw.GetId(), TotpCode: credentials.TOTP(secret, b.clk.Now())}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(done.Header().Values("Set-Cookie"), ";"), "__Host-osadmin-session=") {
		t.Fatal("no session cookie")
	}
	br.csrf = done.Msg.GetSession().GetCsrfToken()
	st := b.store.Read()
	a, ok := st.Admin("alice")
	if !ok || a.Role != access.RoleOwner || !a.HasCredentials() || !st.IsRootOperator("alice") || !strings.HasPrefix(a.Password.Hash, "$argon2id$") {
		t.Fatalf("the first admin %+v, roster %v", a, st.RootOperators())
	}
	if strings.Contains(mustRead(t, b.state+"/access/store.json"), credentials.Base32(secret)) {
		t.Fatal("the TOTP secret is stored in the clear")
	}
	if b.sshdUp != 1 {
		t.Fatalf("sshd started %d times", b.sshdUp)
	}
	if c := b.console(); c.GetFirstAdmin() != "alice" || !c.GetSshOn() || c.GetSetupStep() != 3 {
		t.Fatalf("console after the first admin %v", c)
	}
	_, err = setupClient(b.browser()).RedeemCode(ctx, connect.NewRequest(&osadminv1.RedeemCodeRequest{Code: info.GetSetupCode()}))
	symbolIn(t, err, connect.CodeNotFound, "SETUP_CODE")
	if sealed := string(b.codeSealer.items[onetime.SealedName]); sealed == "" || strings.Contains(sealed, info.GetSetupCode()) {
		t.Fatalf("the setup code wasn't destroyed after the first admin: %q", sealed)
	}

	// The rest of the steps, in order.
	_, err = su.AcknowledgeStep(ctx, connect.NewRequest(&osadminv1.AcknowledgeStepRequest{Step: osadminv1.SetupStepKind_SETUP_STEP_KIND_NETWORK}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_INCOMPLETE")
	if _, err := su.AddRecoveryKey(ctx, connect.NewRequest(&osadminv1.AddRecoveryKeyRequest{PublicKey: newKey(t).line, Label: "safe"})); err != nil {
		t.Fatal(err)
	}
	_, err = su.AcknowledgeStep(ctx, connect.NewRequest(&osadminv1.AcknowledgeStepRequest{Step: osadminv1.SetupStepKind_SETUP_STEP_KIND_PROTECTION}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_INCOMPLETE")
	for _, s := range []osadminv1.SetupStepKind{osadminv1.SetupStepKind_SETUP_STEP_KIND_NETWORK, osadminv1.SetupStepKind_SETUP_STEP_KIND_PROTECTION} {
		if _, err := su.AcknowledgeStep(ctx, connect.NewRequest(&osadminv1.AcknowledgeStepRequest{Step: s})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := su.AcknowledgeSingleAdmin(ctx, connect.NewRequest(&osadminv1.AcknowledgeSingleAdminRequest{})); err != nil {
		t.Fatal(err)
	}
	_, err = su.Finish(ctx, connect.NewRequest(&osadminv1.FinishRequest{}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "sign in once")
	if _, err := trySignIn(br, "alice", testPassword, credentials.TOTP(secret, b.clk.Now().Add(30*time.Second))); err != nil {
		t.Fatal(err)
	}
	br.signInCSRF(t)
	if _, err := su.Finish(ctx, connect.NewRequest(&osadminv1.FinishRequest{})); err != nil {
		t.Fatal(err)
	}
	if c := b.console(); c.GetState() != accessv1.SetupState_SETUP_STATE_DONE {
		t.Fatalf("console after Finish %v", c)
	}
}

// signInCSRF picks up the CSRF token of the session the last sign-in set.
func (br *browser) signInCSRF(t *testing.T) {
	t.Helper()
	g, err := signInClient(br).GetSession(context.Background(), connect.NewRequest(&osadminv1.GetSessionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	br.csrf = g.Msg.GetSession().GetCsrfToken()
}

func TestFiveWrongSetupCodesLockItOut(t *testing.T) {
	b := newFreshBox(t)
	first := b.console().GetSetupCode()
	su := setupClient(b.browser())
	for range onetime.MaxAttempts {
		_, _ = su.RedeemCode(context.Background(), connect.NewRequest(&osadminv1.RedeemCodeRequest{Code: "0000-0000-0000-0000"}))
	}
	info := b.console()
	if info.GetSetupCode() != "" || !info.GetCodeLocked() {
		t.Fatalf("after five wrong codes the console shows %v", info)
	}
	_, err := su.RedeemCode(context.Background(), connect.NewRequest(&osadminv1.RedeemCodeRequest{Code: first}))
	symbolIn(t, err, connect.CodeNotFound, "SETUP_CODE")
	b.srv.ResetSetupCode()
	if next := b.console().GetSetupCode(); next == "" || next == first {
		t.Fatalf("the console's new code %q", next)
	}
}

func TestTheSetupCodeLastsSixtyMinutes(t *testing.T) {
	b := newFreshBox(t)
	code := b.console().GetSetupCode()
	b.clk.Advance(60 * time.Minute)
	_, err := setupClient(b.browser()).RedeemCode(context.Background(), connect.NewRequest(&osadminv1.RedeemCodeRequest{Code: code}))
	symbolIn(t, err, connect.CodeNotFound, "SETUP_CODE")
	if b.console().GetSetupCode() == code {
		t.Fatal("the expired code is still shown")
	}
}

func TestOnlyTheAllowListMayTryACode(t *testing.T) {
	b := newFreshBox(t)
	b.netd.settings.AllowList = []string{"192.0.2.0/24"}
	_, err := setupClient(b.browser()).RedeemCode(context.Background(), connect.NewRequest(&osadminv1.RedeemCodeRequest{Code: b.console().GetSetupCode()}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	b.netd.settings.AllowList = []string{"127.0.0.0/8"}
	if _, err := setupClient(b.browser()).RedeemCode(context.Background(), connect.NewRequest(&osadminv1.RedeemCodeRequest{Code: b.console().GetSetupCode()})); err != nil {
		t.Fatal(err)
	}
}

// The console's "this isn't you" stops the browser setup and shows a new
// code.
func TestTheConsoleStopsABrowserSetup(t *testing.T) {
	b := newFreshBox(t)
	br := b.browser()
	code := b.console().GetSetupCode()
	red, err := setupClient(br).RedeemCode(context.Background(), connect.NewRequest(&osadminv1.RedeemCodeRequest{Code: code}))
	if err != nil {
		t.Fatal(err)
	}
	br.csrf = red.Msg.GetCsrfToken()
	b.srv.ResetSetupCode()
	_, err = setupClient(br).BeginCredentials(context.Background(), connect.NewRequest(&osadminv1.BeginCredentialsRequest{Admin: "alice", Password: testPassword}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
	if c := b.console(); c.GetState() != accessv1.SetupState_SETUP_STATE_NOT_STARTED || c.GetSetupCode() == code {
		t.Fatalf("console %v", c)
	}
	if e := lastEntry(t, b.log, "setup.code.reset"); e.Detail["sessionsEnded"] != "1" {
		t.Fatalf("audit %+v", e)
	}
}

// A quiet setup browser gives the code back: after 30 minutes without a
// call the console shows a new code.
func TestAQuietSetupBrowserGivesTheCodeBack(t *testing.T) {
	b := newFreshBox(t)
	if _, err := setupClient(b.browser()).RedeemCode(context.Background(), connect.NewRequest(&osadminv1.RedeemCodeRequest{Code: b.console().GetSetupCode()})); err != nil {
		t.Fatal(err)
	}
	b.clk.Advance(31 * time.Minute)
	if c := b.console(); c.GetState() != accessv1.SetupState_SETUP_STATE_NOT_STARTED || c.GetSetupCode() == "" {
		t.Fatalf("console %v", c)
	}
}

// The console's Recover access gives an owner a new password and
// authenticator; every admin sees a notice at their next sign-in.
func TestRecoverAccessResetsAnOwner(t *testing.T) {
	b := newBox(t, true)
	code, _ := b.srv.BeginRecoverAccess()
	if r := b.console().GetRecover(); r.GetCode() != code || r.GetUrl() != "https://192.0.2.10:8443/recover" {
		t.Fatalf("console %v", r)
	}
	br := b.browser()
	red, err := setupClient(br).RedeemCode(context.Background(), connect.NewRequest(&osadminv1.RedeemCodeRequest{Code: code}))
	if err != nil || red.Msg.GetKind() != osadminv1.CodeKind_CODE_KIND_RECOVER || !slices.Equal(red.Msg.GetExistingOwners(), []string{"alice"}) {
		t.Fatalf("redeem %v %v", red, err)
	}
	br.csrf = red.Msg.GetCsrfToken()
	_, err = setupClient(br).BeginCredentials(context.Background(), connect.NewRequest(&osadminv1.BeginCredentialsRequest{Admin: "bob", Password: "a recovered passphrase"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	for range 3 {
		_, _ = trySignIn(b.browser(), "alice", "forgotten", "000000")
	}
	b.srv.CancelRecoverAccess()
	code, _ = b.srv.BeginRecoverAccess()
	secret := b.browser().enrol(t, code, "alice", "a recovered passphrase")
	if _, err := trySignIn(b.browser(), "alice", testPassword, b.code("alice")); err == nil {
		t.Fatal("the old password still works")
	}
	if _, err := trySignIn(b.browser(), "alice", "a recovered passphrase", credentials.TOTP(secret, b.clk.Now().Add(30*time.Second))); err != nil {
		t.Fatalf("the reset clears alice's lock and her new credentials work: %v", err)
	}
	s, err := trySignIn(b.browser(), "bob", testPassword, b.code("bob"))
	if err != nil || len(s.Msg.GetSession().GetNotices()) != 1 || !strings.Contains(s.Msg.GetSession().GetNotices()[0], "Recover access") {
		t.Fatalf("bob's notice: %v %v", s, err)
	}
	if b.store.Read().LastRecoverAccess == nil {
		t.Fatal("not recorded")
	}
	if b.console().GetRecover() != nil {
		t.Fatal("the used code is still shown")
	}
}

// Recover access can also make a new owner, on the root-operator roster.
func TestRecoverAccessMakesANewOwner(t *testing.T) {
	b := newBox(t, false)
	if err := b.store.Update(rosterOf("alice")); err != nil {
		t.Fatal(err)
	}
	code, _ := b.srv.BeginRecoverAccess()
	secret := b.browser().enrol(t, code, "dave", "dave's long passphrase")
	st := b.store.Read()
	a, ok := st.Admin("dave")
	if !ok || a.Role != access.RoleOwner || !st.IsRootOperator("dave") || a.CreatedBy != "recover-access" {
		t.Fatalf("%+v %v", a, st.RootOperators())
	}
	if _, err := trySignIn(b.browser(), "dave", "dave's long passphrase", credentials.TOTP(secret, b.clk.Now().Add(30*time.Second))); err != nil {
		t.Fatal(err)
	}
}
