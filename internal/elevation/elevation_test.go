// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package elevation_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

type memAudit struct {
	mu sync.Mutex
	es []osaudit.Entry
}

func (m *memAudit) Append(e osaudit.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.es = append(m.es, e)
	return nil
}

func (m *memAudit) last(action string) (osaudit.Entry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.es) - 1; i >= 0; i-- {
		if m.es[i].Action == action {
			return m.es[i], true
		}
	}
	return osaudit.Entry{}, false
}

// memSealer stands in for init's KeyCustody.
type memSealer struct {
	items   map[string][]byte
	sealErr error
}

func newMemSealer() *memSealer { return &memSealer{items: map[string][]byte{}} }

func (m *memSealer) Seal(name string, secret []byte) error {
	if m.sealErr != nil {
		return m.sealErr
	}
	m.items[name] = slices.Clone(secret)
	return nil
}

func (m *memSealer) Unseal(name string) ([]byte, bool, error) {
	b, ok := m.items[name]
	return slices.Clone(b), ok, nil
}

type fixture struct {
	t       *testing.T
	sealer  *memSealer
	dir     string
	clk     *clock.Fake
	audit   *memAudit
	svc     *elevation.Service
	st      access.State
	keys    map[string]ssh.PublicKey
	changes int
	signals []int
	maint   bool
}

func newFixture(t *testing.T, owners ...string) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: t.TempDir(), clk: clock.NewFake(), audit: &memAudit{}, keys: map[string]ssh.PublicKey{}, sealer: newMemSealer()}
	f.st = access.State{ElevationPolicy: access.DefaultPolicy()}
	for _, o := range owners {
		f.addAdmin(o, access.RoleOwner)
	}
	f.addAdmin("bob", access.RoleAdmin)
	f.open()
	return f
}

func (f *fixture) open() {
	f.t.Helper()
	svc, err := elevation.Open(elevation.Options{
		SSHDir:      filepath.Join(f.dir, "ssh"),
		StateFile:   filepath.Join(f.dir, "access", "elevation.json"),
		Sealer:      f.sealer,
		Clock:       f.clk,
		Audit:       f.audit,
		Maintenance: func() bool { return f.maint },
		Signal:      func(pid int) error { f.signals = append(f.signals, pid); return nil },
		OnChange:    func() { f.changes++ },
	})
	if err != nil {
		f.t.Fatal(err)
	}
	f.svc = svc
}

func (f *fixture) addAdmin(name string, role access.Role) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		f.t.Fatal(err)
	}
	k, err := access.ParseLoginKey(string(ssh.MarshalAuthorizedKey(pk)))
	if err != nil {
		f.t.Fatal(err)
	}
	f.st.Admins = append(f.st.Admins, access.Admin{Name: name, UID: access.FirstUID + len(f.st.Admins), Role: role, Keys: []access.AdminKey{{Key: k}}})
	f.keys[name] = pk
}

func (f *fixture) request(admin string, minutes int) elevation.Request {
	f.t.Helper()
	r, err := f.svc.Request(f.st, elevation.Caller{Admin: admin, KeyFP: ssh.FingerprintSHA256(f.keys[admin]), Source: "192.0.2.50"}, "investigate kubelet", minutes)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func wantCode(t *testing.T, err error, code int) {
	t.Helper()
	if got, ok := codes.Of(err); !ok || got != code {
		t.Fatalf("want %s, got %v", codes.Symbol(code), err)
	}
}

func parseCert(t *testing.T, line string) *ssh.Certificate {
	t.Helper()
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatalf("not a certificate: %T", pk)
	}
	return c
}

func TestTheUserCAIsSealedAndMadeOnce(t *testing.T) {
	f := newFixture(t, "alice")
	priv := filepath.Join(f.dir, "ssh", elevation.UserCAFile)
	if _, err := os.Stat(priv); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the CA's private key is on disk: %v", err)
	}
	sealed, ok := f.sealer.items[elevation.SealedName]
	if !ok {
		t.Fatal("the CA isn't sealed")
	}
	if _, err := ssh.ParsePrivateKey(sealed); err != nil {
		t.Fatalf("the sealed CA doesn't parse: %v", err)
	}
	pub, err := os.ReadFile(priv + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	ca, _, _, _, err := ssh.ParseAuthorizedKey(pub)
	if err != nil || ca.Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("%v %v", ca, err)
	}
	before := f.svc.UserCA().Marshal()
	f.open()
	if !slices.Equal(before, f.svc.UserCA().Marshal()) {
		t.Fatal("a restart made a new user CA")
	}
}

// interimCA writes a CA key file the way accessd kept it before the CA was
// sealed, and returns its public key.
func interimCA(t *testing.T, dir string) ssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ssh", elevation.UserCAFile), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s.PublicKey()
}

func TestAnInterimCAFileMovesIntoTheSealedItem(t *testing.T) {
	f := &fixture{t: t, dir: t.TempDir(), clk: clock.NewFake(), audit: &memAudit{}, keys: map[string]ssh.PublicKey{}, sealer: newMemSealer()}
	want := interimCA(t, f.dir)
	f.open()
	if !slices.Equal(f.svc.UserCA().Marshal(), want.Marshal()) {
		t.Fatal("the box's CA changed in the move: elevation certificates would stop working")
	}
	if _, err := os.Stat(filepath.Join(f.dir, "ssh", elevation.UserCAFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the interim file is still there: %v", err)
	}
	if _, ok := f.sealer.items[elevation.SealedName]; !ok {
		t.Fatal("the CA wasn't sealed")
	}
	f.open()
	if !slices.Equal(f.svc.UserCA().Marshal(), want.Marshal()) {
		t.Fatal("the CA changed on the next start")
	}
}

func TestAnInterimCAFileStaysUntilItIsSealed(t *testing.T) {
	dir := t.TempDir()
	interimCA(t, dir)
	failing := newMemSealer()
	failing.sealErr = errors.New("KEYCUSTODY_LOCKED: the state isn't unlocked")
	_, err := elevation.Open(elevation.Options{
		SSHDir: filepath.Join(dir, "ssh"), StateFile: filepath.Join(dir, "access", "elevation.json"), Sealer: failing,
	})
	if err == nil {
		t.Fatal("opened without sealing the CA")
	}
	if _, err := os.Stat(filepath.Join(dir, "ssh", elevation.UserCAFile)); err != nil {
		t.Fatalf("the interim file went before the CA was sealed: %v", err)
	}
}

func TestARequestTakesTheCallersKeyAndThePolicy(t *testing.T) {
	f := newFixture(t, "alice")
	r := f.request("bob", 0)
	if r.State != elevation.Pending || r.Minutes != 60 || r.Admin != "bob" || r.Source != "192.0.2.50" || !strings.HasPrefix(r.ID, "E-") || len(r.ID) != 6 {
		t.Fatalf("%+v", r)
	}
	if e, ok := f.audit.last("elevation.request"); !ok || e.Actor != "bob" || e.Target != r.ID || e.Outcome != "ok" {
		t.Fatalf("%+v", e)
	}
	for _, m := range []int{14, 241} {
		_, err := f.svc.Request(f.st, elevation.Caller{Admin: "bob", KeyFP: ssh.FingerprintSHA256(f.keys["bob"]), Source: "192.0.2.50"}, "x", m)
		wantCode(t, err, codes.ElevMinutes)
	}
	_, err := f.svc.Request(f.st, elevation.Caller{Admin: "bob", KeyFP: ssh.FingerprintSHA256(f.keys["alice"]), Source: "192.0.2.50"}, "x", 30)
	wantCode(t, err, codes.AccessForbidden)
	_, err = f.svc.Request(f.st, elevation.Caller{Admin: "bob", KeyFP: ssh.FingerprintSHA256(f.keys["bob"]), Source: "192.0.2.50"}, " ", 30)
	wantCode(t, err, codes.ShellParse)
	_, err = f.svc.Request(f.st, elevation.Caller{Admin: "bob", KeyFP: ssh.FingerprintSHA256(f.keys["bob"])}, "x", 30)
	wantCode(t, err, codes.AccessForbidden)
}

func TestAnApprovalSignsASingleUseCertificate(t *testing.T) {
	f := newFixture(t, "alice")
	r := f.request("bob", 60)
	a, err := f.svc.Approve(f.st, "alice", r.ID, 30)
	if err != nil {
		t.Fatal(err)
	}
	if a.State != elevation.Approved || a.Minutes != 30 || a.ApprovedBy != "alice" || a.SelfApproved || a.Serial == 0 {
		t.Fatalf("%+v", a)
	}
	c := parseCert(t, a.Certificate)
	now := f.clk.Now()
	if c.CertType != ssh.UserCert || !slices.Equal(c.ValidPrincipals, []string{"elev-" + r.ID}) ||
		c.KeyId != "elev-"+r.ID+" admin=bob fp="+ssh.FingerprintSHA256(f.keys["bob"]) || c.Serial != a.Serial {
		t.Fatalf("%+v", c)
	}
	if int64(c.ValidAfter) > now.Unix() || int64(c.ValidBefore) != now.Add(10*time.Minute).Unix() { // #nosec G115 -- test times
		t.Fatalf("validity %d %d", c.ValidAfter, c.ValidBefore)
	}
	if c.CriticalOptions["force-command"] != "/usr/libexec/sneakers-elevated" || c.CriticalOptions["source-address"] != "192.0.2.50" || len(c.CriticalOptions) != 2 {
		t.Fatalf("critical options %v", c.CriticalOptions)
	}
	if len(c.Extensions) != 1 || c.Extensions["permit-pty"] != "" {
		t.Fatalf("extensions %v", c.Extensions)
	}
	if !slices.Equal(c.Key.Marshal(), f.keys["bob"].Marshal()) || !slices.Equal(c.SignatureKey.Marshal(), f.svc.UserCA().Marshal()) {
		t.Fatal("the certificate isn't for bob's key, signed by the user CA")
	}
	if got := f.svc.Principals(); !slices.Equal(got, []string{"elev-" + r.ID}) || f.changes == 0 {
		t.Fatalf("principals %v, changes %d", got, f.changes)
	}
	if e, ok := f.audit.last("elevation.certificate"); !ok || e.Target != r.ID || e.Actor != "alice" {
		t.Fatalf("%+v", e)
	}
	// The next certificate gets the next serial, across a restart.
	f.open()
	r2 := f.request("bob", 30)
	a2, err := f.svc.Approve(f.st, "alice", r2.ID, 0)
	if err != nil || a2.Serial != a.Serial+1 {
		t.Fatalf("%+v %v", a2, err)
	}
}

func TestOnlyAnOwnerApprovesAndNeverLengthens(t *testing.T) {
	f := newFixture(t, "alice")
	r := f.request("bob", 30)
	_, err := f.svc.Approve(f.st, "bob", r.ID, 0)
	wantCode(t, err, codes.AccessForbidden)
	_, err = f.svc.Approve(f.st, "alice", r.ID, 45)
	wantCode(t, err, codes.ElevMinutes)
	_, err = f.svc.Approve(f.st, "alice", r.ID, 10)
	wantCode(t, err, codes.ElevMinutes)
	_, err = f.svc.Approve(f.st, "alice", "E-ZZZZ", 0)
	wantCode(t, err, codes.ElevUnknown)
	if a, err := f.svc.Approve(f.st, elevation.ConsoleApprover, r.ID, 0); err != nil || a.ApprovedBy != "console" {
		t.Fatalf("the console approves as an owner: %+v %v", a, err)
	}
	_, err = f.svc.Approve(f.st, "alice", r.ID, 0)
	wantCode(t, err, codes.ElevUsed)
}

func TestTheOnlyOwnerMaySelfApproveFlagged(t *testing.T) {
	f := newFixture(t, "alice")
	r := f.request("alice", 30)
	a, err := f.svc.Approve(f.st, "alice", r.ID, 0)
	if err != nil || !a.SelfApproved {
		t.Fatalf("%+v %v", a, err)
	}
	if e, _ := f.audit.last("elevation.certificate"); e.Detail["selfApproved"] != "true" {
		t.Fatalf("%+v", e)
	}
	f.st.ElevationPolicy.SelfApprovalWhenSingleOwner = false
	r2 := f.request("alice", 30)
	_, err = f.svc.Approve(f.st, "alice", r2.ID, 0)
	wantCode(t, err, codes.ElevSelfApproval)
}

func TestWithTwoOwnersNobodyApprovesTheirOwn(t *testing.T) {
	f := newFixture(t, "alice", "carol")
	r := f.request("alice", 30)
	_, err := f.svc.Approve(f.st, "alice", r.ID, 0)
	wantCode(t, err, codes.ElevSelfApproval)
	a, err := f.svc.Approve(f.st, "carol", r.ID, 0)
	if err != nil || a.SelfApproved {
		t.Fatalf("%+v %v", a, err)
	}
}

// An owner named console is an owner like any other: the two-person rule
// applies to them.
func TestAnOwnerNamedConsoleIsNotTheConsole(t *testing.T) {
	f := newFixture(t, "console", "carol")
	r := f.request("console", 30)
	_, err := f.svc.Approve(f.st, "console", r.ID, 0)
	wantCode(t, err, codes.ElevSelfApproval)
}

func TestHoldsAndMaintenanceBlockApproval(t *testing.T) {
	f := newFixture(t, "alice", "carol")
	r := f.request("bob", 30)
	until := f.clk.Now().Add(time.Hour)
	f.st.Admins[0].ApprovalHoldUntil = &until
	_, err := f.svc.Approve(f.st, "alice", r.ID, 0)
	wantCode(t, err, codes.ElevHold)
	f.maint = true
	_, err = f.svc.Approve(f.st, "carol", r.ID, 0)
	wantCode(t, err, codes.ElevMaintenance)
}

// While an update is applied, nobody gets a new elevated shell: a request,
// an approval and the first use of an approved certificate are refused.
func TestMaintenanceRefusesRequestsAndConnects(t *testing.T) {
	f := newFixture(t, "alice")
	approved := f.request("bob", 30)
	a, err := f.svc.Approve(f.st, "alice", approved.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.maint = true
	_, err = f.svc.Request(f.st, elevation.Caller{Admin: "bob", KeyFP: ssh.FingerprintSHA256(f.keys["bob"]), Source: "192.0.2.50"}, "investigate kubelet", 30)
	wantCode(t, err, codes.ElevMaintenance)
	if e, ok := f.audit.last("elevation.request"); !ok || e.Outcome != "refused" || e.Code != "ELEV_MAINTENANCE" {
		t.Fatalf("%+v %v", e, ok)
	}
	_, _, err = f.svc.Begin(a.Certificate, 1)
	wantCode(t, err, codes.ElevMaintenance)
	f.maint = false
	if _, _, err := f.svc.Begin(a.Certificate, 1); err != nil {
		t.Fatalf("after the update the certificate still works in its window: %v", err)
	}
}

func TestWithdraw(t *testing.T) {
	f := newFixture(t, "alice")
	r := f.request("bob", 30)
	w, err := f.svc.Withdraw("bob", r.ID)
	if err != nil || w.State != elevation.Withdrawn || w.EndReason != "withdrawn" {
		t.Fatalf("%+v %v", w, err)
	}
	if e, ok := f.audit.last("elevation.withdraw"); !ok || e.Target != r.ID || e.Actor != "bob" {
		t.Fatalf("%+v %v", e, ok)
	}
	// A withdrawn request can't be approved afterwards.
	_, err = f.svc.Approve(f.st, "alice", r.ID, 0)
	wantCode(t, err, codes.ElevUsed)
	// Withdrawing it again, or a request that was never bob's, is refused.
	_, err = f.svc.Withdraw("bob", r.ID)
	wantCode(t, err, codes.ElevUsed)
	r2 := f.request("bob", 30)
	_, err = f.svc.Withdraw("alice", r2.ID)
	wantCode(t, err, codes.ElevUnknown)
}

func TestDenyAndExpiry(t *testing.T) {
	f := newFixture(t, "alice")
	r := f.request("bob", 30)
	d, err := f.svc.Deny(r.ID, "alice")
	if err != nil || d.State != elevation.Denied || d.EndReason != "denied" {
		t.Fatalf("%+v %v", d, err)
	}
	_, err = f.svc.Approve(f.st, "alice", r.ID, 0)
	wantCode(t, err, codes.ElevUsed)

	r2 := f.request("bob", 30)
	f.clk.Advance(31 * time.Minute)
	_, err = f.svc.Approve(f.st, "alice", r2.ID, 0)
	wantCode(t, err, codes.ElevExpired)
	if g, _ := f.svc.Get(r2.ID); g.State != elevation.Expired {
		t.Fatalf("%+v", g)
	}

	r3 := f.request("bob", 30)
	a3, err := f.svc.Approve(f.st, "alice", r3.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(11 * time.Minute)
	f.svc.Sweep()
	if g, _ := f.svc.Get(r3.ID); g.State != elevation.Expired || len(f.svc.Principals()) != 0 {
		t.Fatalf("%+v %v", g, f.svc.Principals())
	}
	if !slices.Contains(f.svc.Revoked(), a3.Serial) {
		t.Fatalf("an expired certificate's serial isn't revoked: %v", f.svc.Revoked())
	}
	if e, ok := f.audit.last("elevation.expire"); !ok || e.Target != r3.ID {
		t.Fatalf("%+v", e)
	}
}

func TestBeginUsesTheCertificateOnce(t *testing.T) {
	f := newFixture(t, "alice")
	r := f.request("bob", 30)
	a, err := f.svc.Approve(f.st, "alice", r.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(2 * time.Minute)
	got, ends, err := f.svc.Begin(a.Certificate, 4242)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != elevation.Active || got.PID != 4242 || !ends.Equal(f.clk.Now().Add(30*time.Minute)) {
		t.Fatalf("%+v %v", got, ends)
	}
	if len(f.svc.Principals()) != 0 || !slices.Contains(f.svc.Revoked(), a.Serial) || !f.svc.Active() {
		t.Fatalf("principals %v revoked %v", f.svc.Principals(), f.svc.Revoked())
	}
	krl, err := os.ReadFile(filepath.Join(f.dir, "ssh", elevation.RevokedFile))
	if err != nil || !strings.HasPrefix(string(krl), "SSHKRL\n\x00") {
		t.Fatalf("revocation list %q %v", krl, err)
	}
	_, _, err = f.svc.Begin(a.Certificate, 4243)
	wantCode(t, err, codes.ElevUsed)
	if e, ok := f.audit.last("elevation.connect"); !ok || e.Target != r.ID || e.Actor != "bob" {
		t.Fatalf("%+v", e)
	}
	if err := f.svc.End(r.ID, "exit", "abc123"); err != nil {
		t.Fatal(err)
	}
	g, _ := f.svc.Get(r.ID)
	if g.State != elevation.Ended || g.EndReason != "exit" || g.RecordingSHA256 != "abc123" || f.svc.Active() {
		t.Fatalf("%+v", g)
	}
	if e, ok := f.audit.last("elevation.end"); !ok || e.Outcome != "exit" || e.Detail["recordingSha256"] != "abc123" {
		t.Fatalf("%+v", e)
	}
}

func TestBeginRefusesForeignAndLateCertificates(t *testing.T) {
	f := newFixture(t, "alice")
	r := f.request("bob", 30)
	a, err := f.svc.Approve(f.st, "alice", r.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The same certificate signed by another CA.
	c := parseCert(t, a.Certificate)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(other)
	if err := c.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	_, _, err = f.svc.Begin(string(ssh.MarshalAuthorizedKey(c)), 1)
	wantCode(t, err, codes.ElevUnknown)
	f.clk.Advance(11 * time.Minute)
	_, _, err = f.svc.Begin(a.Certificate, 1)
	wantCode(t, err, codes.ElevExpired)
}

func TestTerminate(t *testing.T) {
	f := newFixture(t, "alice")
	r := f.request("bob", 30)
	a, _ := f.svc.Approve(f.st, "alice", r.ID, 0)
	if _, _, err := f.svc.Begin(a.Certificate, 4242); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Terminate(r.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.signals, []int{4242}) {
		t.Fatalf("signals %v", f.signals)
	}
	// An approved, unused certificate is revoked by a terminate.
	r2 := f.request("bob", 30)
	a2, _ := f.svc.Approve(f.st, "alice", r2.ID, 0)
	g, err := f.svc.Terminate(r2.ID, "alice")
	if err != nil || g.State != elevation.Expired || g.EndReason != "terminated" || !slices.Contains(f.svc.Revoked(), a2.Serial) {
		t.Fatalf("%+v %v", g, err)
	}
	_, err = f.svc.Terminate(r2.ID, "alice")
	wantCode(t, err, codes.ElevUsed)
}

func TestTheRequesterAloneFetchesTheCertificate(t *testing.T) {
	f := newFixture(t, "alice")
	r := f.request("bob", 30)
	_, err := f.svc.Certificate("bob", r.ID)
	wantCode(t, err, codes.ElevUnknown)
	a, _ := f.svc.Approve(f.st, "alice", r.ID, 0)
	_, err = f.svc.Certificate("alice", r.ID)
	wantCode(t, err, codes.ElevUnknown)
	got, err := f.svc.Certificate("bob", r.ID)
	if err != nil || got.Certificate != a.Certificate {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestHistorySurvivesARestart(t *testing.T) {
	f := newFixture(t, "alice")
	r := f.request("bob", 30)
	f.open()
	g, ok := f.svc.Get(r.ID)
	if !ok || g.State != elevation.Pending || len(f.svc.List()) != 1 {
		t.Fatalf("%+v %v", g, ok)
	}
}
