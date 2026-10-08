// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/credentials"
)

func TestRoles(t *testing.T) {
	b := newBox(t, true)
	bob := b.browser()
	bob.signIn("bob")
	ctx := context.Background()
	_, err := bob.access().AddAdmin(ctx, connect.NewRequest(&osadminv1.AddAdminRequest{Name: "carol", Role: osadminv1.Role_ROLE_ADMIN}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	_, err = bob.access().RemoveKey(ctx, connect.NewRequest(&osadminv1.RemoveKeyRequest{Admin: "alice", Fingerprint: b.keys["alice"].fp}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	if _, err := bob.access().IssueSshKey(ctx, connect.NewRequest(&osadminv1.IssueSshKeyRequest{Label: "laptop", TotpCode: b.code("bob")})); err != nil {
		t.Fatalf("an admin gets their own keys: %v", err)
	}
	_, err = bob.access().SetRole(ctx, connect.NewRequest(&osadminv1.SetRoleRequest{Name: "bob", Role: osadminv1.Role_ROLE_OWNER}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	_, err = bob.access().SetAccessPolicy(ctx, connect.NewRequest(&osadminv1.SetAccessPolicyRequest{Policy: &osadminv1.AccessPolicy{LockoutMode: osadminv1.LockoutMode_LOCKOUT_MODE_TIMED, RootCodeMinutes: 5, RootSessionMinutes: 5, SshKeyValidDays: 30}}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")

	alice := b.browser()
	alice.signIn("alice")
	if _, err := alice.access().AddAdmin(ctx, connect.NewRequest(&osadminv1.AddAdminRequest{Name: "carol", Role: osadminv1.Role_ROLE_ADMIN})); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.access().SetRole(ctx, connect.NewRequest(&osadminv1.SetRoleRequest{Name: "bob", Role: osadminv1.Role_ROLE_OWNER})); err != nil {
		t.Fatal(err)
	}
	list, err := bob.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	if err != nil || len(list.Msg.GetAdmins()) != 3 {
		t.Fatalf("%v %v", list, err)
	}
	// A promotion applies to the live session at once.
	bob.stepUp("bob")
	if _, err := bob.access().AddAdmin(ctx, connect.NewRequest(&osadminv1.AddAdminRequest{Name: "dave", Role: osadminv1.Role_ROLE_ADMIN})); err != nil {
		t.Fatalf("bob is an owner now: %v", err)
	}
}

func TestTheLastOwnerStays(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	_, err := alice.access().SetRole(ctx, connect.NewRequest(&osadminv1.SetRoleRequest{Name: "alice", Role: osadminv1.Role_ROLE_ADMIN}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ACCESS_LAST_OWNER")
	_, err = alice.access().RemoveAdmin(ctx, connect.NewRequest(&osadminv1.RemoveAdminRequest{Name: "alice"}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ACCESS_LAST_OWNER")
	// Removing the owner's only SSH key is fine: password and TOTP still
	// sign in on :8443, which issues a new key.
	if _, err := alice.access().RemoveKey(ctx, connect.NewRequest(&osadminv1.RemoveKeyRequest{Admin: "alice", Fingerprint: b.keys["alice"].fp})); err != nil {
		t.Fatal(err)
	}
}

func TestRemovingAnAdminEndsTheirSessions(t *testing.T) {
	b := newBox(t, true)
	ctx := context.Background()
	alice := b.browser()
	alice.signIn("alice")
	bob := b.browser()
	bob.signIn("bob")
	if _, err := alice.access().RemoveAdmin(ctx, connect.NewRequest(&osadminv1.RemoveAdminRequest{Name: "bob"})); err != nil {
		t.Fatal(err)
	}
	_, err := bob.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
}

// The box makes the key pair and signs its certificate with the root key;
// the private key comes back once and is never kept, and revoking the key
// puts its serial on the revocation list.
func TestAnIssuedSSHKey(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	out, err := alice.access().IssueSshKey(ctx, connect.NewRequest(&osadminv1.IssueSshKeyRequest{Label: "laptop", ValidDays: 30, TotpCode: b.code("alice")}))
	if err != nil {
		t.Fatal(err)
	}
	m := out.Msg
	priv, err := ssh.ParsePrivateKey([]byte(m.GetPrivateKey()))
	if err != nil {
		t.Fatalf("the private key doesn't parse: %v", err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(m.GetCertificate()))
	if err != nil {
		t.Fatal(err)
	}
	cert := pk.(*ssh.Certificate)
	if !bytes.Equal(cert.Key.Marshal(), priv.PublicKey().Marshal()) || !bytes.Equal(cert.SignatureKey.Marshal(), b.root.PublicKey().Marshal()) {
		t.Fatal("the certificate isn't the root key's for the issued key")
	}
	checker := ssh.CertChecker{
		IsUserAuthority: func(a ssh.PublicKey) bool { return bytes.Equal(a.Marshal(), b.root.PublicKey().Marshal()) },
		Clock:           b.clk.Now,
	}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Fatalf("the certificate doesn't check for alice: %v", err)
	}
	if got := time.Unix(int64(cert.ValidBefore), 0); got.Sub(b.clk.Now()) < 29*24*time.Hour || got.Sub(b.clk.Now()) > 31*24*time.Hour { // #nosec G115 -- a test time
		t.Fatalf("valid until %v", got)
	}
	if m.GetKey().GetSerial() != cert.Serial || m.GetKey().GetComment() != "laptop" || m.GetKey().GetVia() != "issued" {
		t.Fatalf("key %v", m.GetKey())
	}
	if e := lastEntry(t, b.log, "access.ssh-key.issue"); e.Outcome != "ok" || e.Detail["serial"] == "" {
		t.Fatalf("audit %+v", e)
	}
	stored, err := os.ReadFile(filepath.Join(b.state, "access", "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("PRIVATE KEY")) {
		t.Fatal("the private key was kept")
	}
	again, err := alice.access().IssueSshKey(ctx, connect.NewRequest(&osadminv1.IssueSshKeyRequest{TotpCode: b.code("alice")}))
	if err != nil || again.Msg.GetKey().GetSerial() == m.GetKey().GetSerial() {
		t.Fatalf("a second key reused the serial: %v %v", again, err)
	}
	if _, err := alice.access().RemoveKey(ctx, connect.NewRequest(&osadminv1.RemoveKeyRequest{Admin: "alice", Fingerprint: m.GetKey().GetFingerprint()})); err != nil {
		t.Fatal(err)
	}
	st := b.store.Read()
	if !slices.Contains(st.RevokedSerials(), cert.Serial) {
		t.Fatalf("revoked serials %v", st.RevokedSerials())
	}
	_, err = alice.access().IssueSshKey(ctx, connect.NewRequest(&osadminv1.IssueSshKeyRequest{ValidDays: 5000, TotpCode: b.code("alice")}))
	symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_POLICY")
}

// A new admin gets an invitation code, not a key; the code sets their
// password and authenticator on :8443, and they join the root-operator
// roster when asked.
func TestAnInvitation(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	if err := b.store.Update(rosterOf("alice")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	out, err := alice.access().AddAdmin(ctx, connect.NewRequest(&osadminv1.AddAdminRequest{Name: "carol", Role: osadminv1.Role_ROLE_ADMIN, RootOperator: true}))
	if err != nil {
		t.Fatal(err)
	}
	inv := out.Msg.GetInvitation()
	if len(inv.GetCode()) != 19 || !inv.GetExpires().AsTime().Equal(b.clk.Now().Add(24*time.Hour)) || out.Msg.GetAdmin().GetCredentialsSet() {
		t.Fatalf("invitation %v, admin %v", inv, out.Msg.GetAdmin())
	}
	if st := b.store.Read(); !st.IsRootOperator("carol") || st.EffectiveQuorum().Required != 2 {
		t.Fatalf("roster %+v", st.EffectiveQuorum())
	}
	if strings.Contains(mustRead(t, filepath.Join(b.state, "access", "store.json")), inv.GetCode()) {
		t.Fatal("the store holds a working invitation code")
	}
	carol := b.browser()
	if _, err := trySignIn(carol, "carol", testPassword, "000000"); err == nil {
		t.Fatal("an invited admin signed in before setting a password")
	}
	secret := carol.enrol(t, inv.GetCode(), "carol", "a long enough passphrase")
	if _, err := trySignIn(b.browser(), "carol", "a long enough passphrase", credentials.TOTP(secret, b.clk.Now().Add(30*time.Second))); err != nil {
		t.Fatalf("carol signs in: %v", err)
	}
	// The code worked once.
	_, err = setupClient(b.browser()).RedeemCode(ctx, connect.NewRequest(&osadminv1.RedeemCodeRequest{Code: inv.GetCode()}))
	symbolIn(t, err, connect.CodeNotFound, "SETUP_CODE")
}

func TestChangingThePasswordEndsTheOtherSessions(t *testing.T) {
	b := newBox(t, false)
	ctx := context.Background()
	alice := b.browser()
	alice.signIn("alice")
	other := b.browser()
	other.signIn("alice")
	_, err := alice.access().ChangePassword(ctx, connect.NewRequest(&osadminv1.ChangePasswordRequest{CurrentPassword: "wrong", NewPassword: "a brand new passphrase"}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_CREDENTIALS")
	_, err = alice.access().ChangePassword(ctx, connect.NewRequest(&osadminv1.ChangePasswordRequest{CurrentPassword: testPassword, NewPassword: "short"}))
	symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_PASSWORD")
	if _, err := alice.access().ChangePassword(ctx, connect.NewRequest(&osadminv1.ChangePasswordRequest{CurrentPassword: testPassword, NewPassword: "a brand new passphrase"})); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{})); err != nil {
		t.Fatalf("this session stays: %v", err)
	}
	_, err = other.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
	if _, err := trySignIn(b.browser(), "alice", "a brand new passphrase", b.code("alice")); err != nil {
		t.Fatal(err)
	}
}

func TestReplacingTheAuthenticator(t *testing.T) {
	b := newBox(t, false)
	ctx := context.Background()
	alice := b.browser()
	alice.signIn("alice")
	begin, err := alice.access().BeginTotpReplacement(ctx, connect.NewRequest(&osadminv1.BeginTotpReplacementRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	secret := decodeSecret(t, begin.Msg.GetTotp().GetSecret())
	_, err = alice.access().CompleteTotpReplacement(ctx, connect.NewRequest(&osadminv1.CompleteTotpReplacementRequest{EnrolmentId: begin.Msg.GetTotp().GetId(), TotpCode: "000000"}))
	if err == nil {
		t.Fatal("a wrong first code replaced the authenticator")
	}
	if _, err := alice.access().CompleteTotpReplacement(ctx, connect.NewRequest(&osadminv1.CompleteTotpReplacementRequest{EnrolmentId: begin.Msg.GetTotp().GetId(), TotpCode: credentials.TOTP(secret, b.clk.Now())})); err != nil {
		t.Fatal(err)
	}
	_, err = trySignIn(b.browser(), "alice", testPassword, b.code("alice"))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_CREDENTIALS")
	if _, err := trySignIn(b.browser(), "alice", testPassword, credentials.TOTP(secret, b.clk.Now().Add(30*time.Second))); err != nil {
		t.Fatalf("the new authenticator: %v", err)
	}
}

func TestReinviteClearsTheCredentials(t *testing.T) {
	b := newBox(t, true)
	ctx := context.Background()
	alice := b.browser()
	alice.signIn("alice")
	bob := b.browser()
	bob.signIn("bob")
	_, err := alice.access().ReinviteAdmin(ctx, connect.NewRequest(&osadminv1.ReinviteAdminRequest{Name: "alice"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	out, err := alice.access().ReinviteAdmin(ctx, connect.NewRequest(&osadminv1.ReinviteAdminRequest{Name: "bob"}))
	if err != nil || out.Msg.GetInvitation().GetCode() == "" {
		t.Fatalf("%v %v", out, err)
	}
	_, err = bob.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
	_, err = trySignIn(b.browser(), "bob", testPassword, b.code("bob"))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_CREDENTIALS")
}

func TestHostKeysRootKeyAndPolicy(t *testing.T) {
	b := newBox(t, false)
	dir := filepath.Join(b.state, "ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	hk := newKey(t)
	if err := os.WriteFile(filepath.Join(dir, "ssh_host_ed25519_key.pub"), []byte(hk.line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	policy := &osadminv1.AccessPolicy{LockoutMode: osadminv1.LockoutMode_LOCKOUT_MODE_TIMED, RootCodeMinutes: 5, RootSessionMinutes: 30, SshKeyValidDays: 90}
	if _, err := alice.access().SetAccessPolicy(ctx, connect.NewRequest(&osadminv1.SetAccessPolicyRequest{Policy: policy})); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []*osadminv1.AccessPolicy{
		{LockoutMode: osadminv1.LockoutMode_LOCKOUT_MODE_TIMED, RootCodeMinutes: 61, RootSessionMinutes: 10, SshKeyValidDays: 365},
		{LockoutMode: osadminv1.LockoutMode_LOCKOUT_MODE_TIMED, RootCodeMinutes: 10, RootSessionMinutes: 0, SshKeyValidDays: 365},
		{RootCodeMinutes: 10, RootSessionMinutes: 10, SshKeyValidDays: 365},
	} {
		if _, err := alice.access().SetAccessPolicy(ctx, connect.NewRequest(&osadminv1.SetAccessPolicyRequest{Policy: bad})); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	l, err := alice.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Msg.GetHostKeys()) != 1 || l.Msg.GetHostKeys()[0].GetFingerprint() != hk.fp {
		t.Fatalf("host keys %v", l.Msg.GetHostKeys())
	}
	if p := l.Msg.GetAccessPolicy(); p.GetRootCodeMinutes() != 5 || p.GetRootSessionMinutes() != 30 || p.GetSshKeyValidDays() != 90 {
		t.Fatalf("policy %v", p)
	}
	if rk := l.Msg.GetRootKey(); rk.GetFingerprint() != b.root.Fingerprint() || rk.GetType() != ssh.KeyAlgoED25519 {
		t.Fatalf("root key %v", rk)
	}
	if a := l.Msg.GetAdmins()[0]; !a.GetCredentialsSet() || a.GetPasswordChanged() == nil || a.GetTotpAdded() == nil || !a.GetRootOperator() {
		t.Fatalf("admin %v", a)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) // #nosec G304 -- the test's own file
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Issuing an SSH key mints a credential whose private half leaves the box,
// so it takes a fresh code every time: a fresh sign-in or step-up window
// doesn't count, and a wrong code is a failed try like any other.
func TestIssuingAnSSHKeyTakesAFreshCodeEveryTime(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	keys := func() int {
		st := b.store.Read()
		a, _ := st.Admin("alice")
		return len(a.Keys)
	}
	before := keys()
	_, err := alice.access().IssueSshKey(ctx, connect.NewRequest(&osadminv1.IssueSshKeyRequest{Label: "laptop"}))
	symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_CONFIRM")
	_, err = alice.access().IssueSshKey(ctx, connect.NewRequest(&osadminv1.IssueSshKeyRequest{Label: "laptop", TotpCode: "000000"}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_CREDENTIALS")
	if e := lastEntry(t, b.log, "access.ssh-key.issue"); e.Outcome != "refused" || e.Actor != "alice" {
		t.Fatalf("%+v", e)
	}
	if n := keys() - before; n != 0 {
		t.Fatalf("a refused issue made %d keys", n)
	}
	if _, err := alice.access().IssueSshKey(ctx, connect.NewRequest(&osadminv1.IssueSshKeyRequest{Label: "laptop", TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	_, err = alice.access().IssueSshKey(ctx, connect.NewRequest(&osadminv1.IssueSshKeyRequest{Label: "desk"}))
	symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_CONFIRM")
}
