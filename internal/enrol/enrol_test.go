// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package enrol_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/enrol"
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

func (m *memAudit) actions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, e := range m.es {
		out = append(out, e.Action+":"+e.Outcome)
	}
	return out
}

type fixture struct {
	t       *testing.T
	clk     *clock.Fake
	audit   *memAudit
	store   *access.Store
	svc     *enrol.Service
	changes int
	codes   []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, clk: clock.NewFake(), audit: &memAudit{}}
	var err error
	f.store, err = access.Open(filepath.Join(t.TempDir(), "access"), access.Options{Stage: func() (bool, bool) { return false, false }})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.Update(func(st *access.State) error {
		st.AddAdmin("alice", access.RoleOwner, "console", f.clk.Now())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	n := 0
	f.svc = enrol.New(enrol.Options{
		Store: f.store, Clock: f.clk, Audit: f.audit,
		OnChange: func() { f.changes++ },
		NewCode: func() string {
			n++
			c := []string{"AAAA-BBBB", "CCCC-DDDD", "EEEE-FFFF"}[(n-1)%3]
			f.codes = append(f.codes, c)
			return c
		},
	})
	return f
}

func key(t *testing.T) (string, ssh.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " alice laptop", pk
}

func wantCode(t *testing.T, err error, code int) {
	t.Helper()
	if got, ok := codes.Of(err); !ok || got != code {
		t.Fatalf("want %s, got %v", codes.Symbol(code), err)
	}
}

func TestOutsideAWindowNothingIsTaken(t *testing.T) {
	f := newFixture(t)
	line, _ := key(t)
	_, err := f.svc.Submit("AAAA-BBBB", line, "192.0.2.50")
	wantCode(t, err, codes.EnrolClosed)
	if f.svc.IsOpen() {
		t.Fatal("open before Open")
	}
}

func TestAKeyIsStoredOnlyAfterTheConsolesYes(t *testing.T) {
	f := newFixture(t)
	v, err := f.svc.Open("alice")
	if err != nil {
		t.Fatal(err)
	}
	if !v.Open || v.Code != "AAAA-BBBB" || v.AttemptsLeft != 3 || v.Admin != "alice" || !f.svc.IsOpen() || f.changes != 1 {
		t.Fatalf("%+v changes %d", v, f.changes)
	}
	line, pk := key(t)
	k, err := f.svc.Submit("aaaa bbbb", line, "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	if k.State != enrol.Waiting || k.Fingerprint != ssh.FingerprintSHA256(pk) || k.Comment != "alice laptop" || k.Source != "192.0.2.50" {
		t.Fatalf("%+v", k)
	}
	st := f.store.Read()
	if a, _ := st.Admin("alice"); len(a.Keys) != 0 {
		t.Fatal("a key was stored before the console said yes")
	}
	_, err = f.svc.Accept(k.ID, "y")
	wantCode(t, err, codes.AccessConfirm)
	if _, err := f.svc.Accept(k.ID, "yes"); err != nil {
		t.Fatal(err)
	}
	st = f.store.Read()
	a, _ := st.Admin("alice")
	if len(a.Keys) != 1 || a.Keys[0].Via != access.ViaEnrol || a.Keys[0].AddedBy != "console" {
		t.Fatalf("%+v", a.Keys)
	}
	got, err := f.svc.Key(k.ID)
	if err != nil || got.State != enrol.Accepted {
		t.Fatalf("%+v %v", got, err)
	}
	if v := f.svc.Get(); v.Enrolled != 1 {
		t.Fatalf("%+v", v)
	}
	_, err = f.svc.Accept("K-NOPE", "yes")
	wantCode(t, err, codes.EnrolUnknown)
}

func TestARejectedKeyIsNotStored(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Open("alice"); err != nil {
		t.Fatal(err)
	}
	line, _ := key(t)
	k, err := f.svc.Submit("AAAA-BBBB", line, "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Reject(k.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := f.svc.Key(k.ID)
	st := f.store.Read()
	if a, _ := st.Admin("alice"); got.State != enrol.Rejected || len(a.Keys) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestThreeWrongCodesCloseTheWindowAndShowANewCode(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Open("alice"); err != nil {
		t.Fatal(err)
	}
	line, _ := key(t)
	waiting, err := f.svc.Submit("AAAA-BBBB", line, "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		_, err := f.svc.Submit("ZZZZ-ZZZZ", line, "192.0.2.66")
		wantCode(t, err, codes.EnrolCode)
		if i < 2 && !strings.Contains(err.Error(), "attempt") {
			t.Fatalf("no attempts left in %v", err)
		}
	}
	v := f.svc.Get()
	if !v.Open || v.Code != "CCCC-DDDD" || v.AttemptsLeft != 3 || len(v.Keys) != 0 {
		t.Fatalf("%+v", v)
	}
	_, err = f.svc.Submit("AAAA-BBBB", line, "192.0.2.50")
	wantCode(t, err, codes.EnrolCode)
	_, err = f.svc.Key(waiting.ID)
	wantCode(t, err, codes.EnrolUnknown)
	acts := strings.Join(f.audit.actions(), " ")
	for _, want := range []string{"enrol.open:ok", "enrol.code:refused", "enrol.close:attempts"} {
		if !strings.Contains(acts, want) {
			t.Errorf("no %s in %s", want, acts)
		}
	}
}

func TestTheWindowClosesAfterThirtyIdleMinutes(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Open("alice"); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(29 * time.Minute)
	line, _ := key(t)
	if _, err := f.svc.Submit("AAAA-BBBB", line, "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(29 * time.Minute)
	f.svc.Sweep()
	if !f.svc.IsOpen() {
		t.Fatal("activity didn't keep the window open")
	}
	f.clk.Advance(2 * time.Minute)
	f.svc.Sweep()
	if f.svc.IsOpen() || f.svc.Get().ClosedReason != enrol.ReasonIdle {
		t.Fatalf("%+v", f.svc.Get())
	}
	_, err := f.svc.Submit("AAAA-BBBB", line, "192.0.2.50")
	wantCode(t, err, codes.EnrolClosed)
}

func TestDoneClosesTheWindow(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Open("alice"); err != nil {
		t.Fatal(err)
	}
	before := f.changes
	f.svc.Close(enrol.ReasonDone)
	if f.svc.IsOpen() || f.changes != before+1 || f.svc.Get().ClosedReason != enrol.ReasonDone {
		t.Fatalf("%+v", f.svc.Get())
	}
}

func TestOnlyAnAdminsWindowOpens(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Open("mallory")
	wantCode(t, err, codes.AccessName)
}

func TestAWeakKeyIsRefusedAtSubmit(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Open("alice"); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.Submit("AAAA-BBBB", "ssh-dss AAAAB3NzaC1kc3MAAACBAP", "192.0.2.50")
	if err == nil {
		t.Fatal("a broken key was taken")
	}
}

// sneakers-enrol-keys prints the offered key back, restricted, so any key
// authenticates as enrol while the window is open.
func TestTheKeysCommandPrintsTheOfferedKeyRestricted(t *testing.T) {
	line, pk := key(t)
	f := strings.Fields(line)
	out, err := enrol.AuthorizedLine(ssh.FingerprintSHA256(pk), f[1], f[0])
	if err != nil || out != "restrict "+f[0]+" "+f[1] {
		t.Fatalf("%q %v", out, err)
	}
	if _, err := enrol.AuthorizedLine("SHA256:other", f[1], f[0]); err == nil {
		t.Fatal("a fingerprint that doesn't match the key was taken")
	}
	if _, err := enrol.AuthorizedLine(ssh.FingerprintSHA256(pk), f[1], "ssh-rsa"); err == nil {
		t.Fatal("a type that doesn't match the key was taken")
	}
	if _, err := enrol.AuthorizedLine("x", "not base64!", "ssh-ed25519"); err == nil {
		t.Fatal("garbage was taken")
	}
}
