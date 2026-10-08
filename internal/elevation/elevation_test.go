// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package elevation_test

import (
	"crypto/ed25519"
	"crypto/rand"
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
	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootkey"
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
type memSealer struct{ items map[string][]byte }

func newMemSealer() *memSealer { return &memSealer{items: map[string][]byte{}} }

func (m *memSealer) Seal(name string, secret []byte) error {
	m.items[name] = slices.Clone(secret)
	return nil
}

func (m *memSealer) Unseal(name string) ([]byte, bool, error) {
	b, ok := m.items[name]
	return slices.Clone(b), ok, nil
}

type fixture struct {
	t       *testing.T
	dir     string
	clk     *clock.Fake
	audit   *memAudit
	root    *rootkey.Key
	svc     *elevation.Service
	st      access.State
	keys    map[string]ssh.PublicKey
	changes int
	signals []int
	maint   bool
}

// newFixture has alice as the root operator and bob as an admin who isn't.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: t.TempDir(), clk: clock.NewFake(), audit: &memAudit{}, keys: map[string]ssh.PublicKey{}}
	var err error
	f.root, err = rootkey.Load(newMemSealer(), filepath.Join(f.dir, "ssh"), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.st = access.State{AccessPolicy: access.DefaultPolicy()}
	f.addAdmin("alice", access.RoleOwner)
	f.addAdmin("bob", access.RoleAdmin)
	f.st.Quorum = &access.QuorumRoster{Members: []string{"alice"}, Required: 1}
	f.open()
	return f
}

func (f *fixture) open() {
	f.t.Helper()
	svc, err := elevation.Open(elevation.Options{
		RootKey:     f.root,
		SSHDir:      filepath.Join(f.dir, "ssh"),
		StateFile:   filepath.Join(f.dir, "access", "elevation.json"),
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
	f.st.Admins = append(f.st.Admins, access.Admin{Name: name, UID: access.FirstUID + len(f.st.Admins), Role: role, Keys: []access.AdminKey{{Key: k, Serial: uint64(len(f.st.Admins) + 1)}}})
	f.keys[name] = pk
}

func (f *fixture) caller(admin string) elevation.Caller {
	return elevation.Caller{Admin: admin, KeyFP: ssh.FingerprintSHA256(f.keys[admin]), Source: "192.0.2.50"}
}

func (f *fixture) challenge(admin string) elevation.Request {
	f.t.Helper()
	r, err := f.svc.Challenge(f.st, f.caller(admin), "investigate kubelet")
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// opened runs a challenge, its code and the typed code, and returns the
// ticket.
func (f *fixture) opened(admin string) (elevation.Request, string) {
	f.t.Helper()
	r := f.challenge(admin)
	_, code, err := f.svc.IssueCode(f.st, admin, r.Challenge)
	if err != nil {
		f.t.Fatal(err)
	}
	r, ticket, err := f.svc.Open(f.st, f.caller(admin), r.Challenge, code)
	if err != nil {
		f.t.Fatal(err)
	}
	return r, ticket
}

func wantCode(t *testing.T, err error, code int) {
	t.Helper()
	if got, ok := codes.Of(err); !ok || got != code {
		t.Fatalf("want %s, got %v", codes.Symbol(code), err)
	}
}

func TestOnlyARootOperatorGetsAChallenge(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Challenge(f.st, f.caller("bob"), "")
	wantCode(t, err, codes.AccessForbidden)
	if e, ok := f.audit.last("rootshell.challenge"); !ok || e.Outcome != "refused" || e.Actor != "bob" {
		t.Fatalf("the refusal wasn't audited: %+v", e)
	}
	c := f.caller("alice")
	c.Source = ""
	_, err = f.svc.Challenge(f.st, c, "")
	wantCode(t, err, codes.AccessForbidden)
	r := f.challenge("alice")
	if len(r.Challenge) != 19 || r.State != elevation.Challenged || r.Minutes != access.DefaultRootMinutes {
		t.Fatalf("challenge %+v", r)
	}
	if !r.ValidBefore.Equal(f.clk.Now().UTC().Truncate(time.Second).Add(10 * time.Minute)) {
		t.Fatalf("the challenge works until %v", r.ValidBefore)
	}
}

func TestTheCodeOpensItsChallengeOnce(t *testing.T) {
	f := newFixture(t)
	r := f.challenge("alice")
	_, code, err := f.svc.IssueCode(f.st, "alice", strings.ToLower(r.Challenge))
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 9 || code[4] != '-' {
		t.Fatalf("code %q", code)
	}
	got, ticket, err := f.svc.Open(f.st, f.caller("alice"), r.Challenge, strings.ReplaceAll(code, "-", " "))
	if err != nil || ticket == "" || got.State != elevation.Opened {
		t.Fatalf("open: %+v %v", got, err)
	}
	_, _, err = f.svc.Open(f.st, f.caller("alice"), r.Challenge, code)
	wantCode(t, err, codes.RootChallenge)
}

func TestACodeIsTiedToItsChallenge(t *testing.T) {
	f := newFixture(t)
	a, b := f.challenge("alice"), f.challenge("alice")
	_, codeA, err := f.svc.IssueCode(f.st, "alice", a.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.IssueCode(f.st, "alice", b.Challenge); err != nil {
		t.Fatal(err)
	}
	_, _, err = f.svc.Open(f.st, f.caller("alice"), b.Challenge, codeA)
	wantCode(t, err, codes.RootCode)
}

func TestSomeoneElsesChallengeGetsNoCode(t *testing.T) {
	f := newFixture(t)
	f.st.Quorum.Members = []string{"alice", "bob"}
	f.st.Quorum.Required = 2
	r := f.challenge("alice")
	_, _, err := f.svc.IssueCode(f.st, "bob", r.Challenge)
	wantCode(t, err, codes.RootChallenge)
	_, _, err = f.svc.IssueCode(f.st, "alice", "NOT-A-CHALLENGE")
	wantCode(t, err, codes.RootChallenge)
	_, _, err = f.svc.IssueCode(f.st, "alice", "0000-0000-0000-0000")
	wantCode(t, err, codes.RootChallenge)
}

func TestACodeTypedFromAnotherAddressIsRefused(t *testing.T) {
	f := newFixture(t)
	r := f.challenge("alice")
	_, code, _ := f.svc.IssueCode(f.st, "alice", r.Challenge)
	c := f.caller("alice")
	c.Source = "192.0.2.99"
	_, _, err := f.svc.Open(f.st, c, r.Challenge, code)
	wantCode(t, err, codes.RootChallenge)
}

func TestThreeWrongCodesCloseTheChallenge(t *testing.T) {
	f := newFixture(t)
	r := f.challenge("alice")
	_, code, _ := f.svc.IssueCode(f.st, "alice", r.Challenge)
	for i := range elevation.MaxCodeTries - 1 {
		_, _, err := f.svc.Open(f.st, f.caller("alice"), r.Challenge, "0000-0000")
		wantCode(t, err, codes.RootCode)
		if !strings.Contains(err.Error(), "tries left") {
			t.Fatalf("try %d: %v", i, err)
		}
	}
	_, _, err := f.svc.Open(f.st, f.caller("alice"), r.Challenge, "0000-0000")
	wantCode(t, err, codes.RootChallenge)
	_, _, err = f.svc.Open(f.st, f.caller("alice"), r.Challenge, code)
	wantCode(t, err, codes.RootChallenge)
	got, _ := f.svc.Get(r.ID)
	if got.State != elevation.Expired || got.EndReason != elevation.ReasonCodeTries {
		t.Fatalf("after three wrong codes %+v", got)
	}
}

func TestTheCodeLapsesAfterTheOwnersLifetime(t *testing.T) {
	f := newFixture(t)
	f.st.AccessPolicy.RootCodeMinutes = 3
	r := f.challenge("alice")
	_, code, _ := f.svc.IssueCode(f.st, "alice", r.Challenge)
	f.clk.Advance(3 * time.Minute)
	_, _, err := f.svc.Open(f.st, f.caller("alice"), r.Challenge, code)
	wantCode(t, err, codes.RootChallenge)
	got, _ := f.svc.Get(r.ID)
	if got.State != elevation.Expired {
		t.Fatalf("state %s", got.State)
	}
}

func TestTheTicketStartsTheShellOnceForItsAdmin(t *testing.T) {
	f := newFixture(t)
	f.st.AccessPolicy.RootSessionMinutes = 25
	r, ticket := f.opened("alice")
	_, _, err := f.svc.Begin(ticket, "bob", 41)
	wantCode(t, err, codes.ElevUnknown)
	got, ends, err := f.svc.Begin(ticket, "alice", 42)
	if err != nil || got.State != elevation.Active || got.PID != 42 {
		t.Fatalf("begin: %+v %v", got, err)
	}
	if !ends.Equal(got.Started.Add(25 * time.Minute)) {
		t.Fatalf("ends %v", ends)
	}
	_, _, err = f.svc.Begin(ticket, "alice", 43)
	wantCode(t, err, codes.ElevUnknown)
	if !f.svc.Active() {
		t.Fatal("no active root shell")
	}
	if err := f.svc.End(r.ID, elevation.ReasonExit, "abc"); err != nil {
		t.Fatal(err)
	}
	got, _ = f.svc.Get(r.ID)
	if got.State != elevation.Ended || got.RecordingSHA256 != "abc" || f.svc.Active() {
		t.Fatalf("after the end %+v", got)
	}
	if e, ok := f.audit.last("rootshell.end"); !ok || e.Outcome != elevation.ReasonExit {
		t.Fatalf("end audit %+v", e)
	}
}

func TestAnUnusedTicketExpires(t *testing.T) {
	f := newFixture(t)
	_, ticket := f.opened("alice")
	f.clk.Advance(elevation.TicketLifetime)
	_, _, err := f.svc.Begin(ticket, "alice", 1)
	wantCode(t, err, codes.ElevExpired)
}

func TestNoRootShellDuringAnUpdate(t *testing.T) {
	f := newFixture(t)
	_, ticket := f.opened("alice")
	f.maint = true
	_, err := f.svc.Challenge(f.st, f.caller("alice"), "")
	wantCode(t, err, codes.ElevMaintenance)
	_, _, err = f.svc.Begin(ticket, "alice", 1)
	wantCode(t, err, codes.ElevMaintenance)
}

func TestTerminateEndsAShellOrClosesAChallenge(t *testing.T) {
	f := newFixture(t)
	r, ticket := f.opened("alice")
	if _, _, err := f.svc.Begin(ticket, "alice", 7); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Terminate(r.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.signals, []int{7}) {
		t.Fatalf("signals %v", f.signals)
	}
	c := f.challenge("alice")
	if _, err := f.svc.Terminate(c.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.svc.Get(c.ID); got.State != elevation.Expired || got.EndReason != elevation.ReasonTerminated {
		t.Fatalf("a closed challenge %+v", got)
	}
}

func TestSweepExpiresAndFindsLostSessions(t *testing.T) {
	f := newFixture(t)
	c := f.challenge("alice")
	r, ticket := f.opened("alice")
	if _, _, err := f.svc.Begin(ticket, "alice", 9); err != nil {
		t.Fatal(err)
	}
	svc, err := elevation.Open(elevation.Options{
		RootKey: f.root, SSHDir: filepath.Join(f.dir, "ssh"), StateFile: filepath.Join(f.dir, "access", "elevation.json"),
		Clock: f.clk, Audit: f.audit, Alive: func(int) bool { return false },
	})
	if err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(11 * time.Minute)
	svc.Sweep()
	if got, _ := svc.Get(c.ID); got.State != elevation.Expired {
		t.Fatalf("an old challenge %+v", got)
	}
	if got, _ := svc.Get(r.ID); got.State != elevation.Ended || got.EndReason != elevation.ReasonLost {
		t.Fatalf("a lost session %+v", got)
	}
}

func TestTheHistorySurvivesARestart(t *testing.T) {
	f := newFixture(t)
	r := f.challenge("alice")
	f.open()
	if got, ok := f.svc.Get(r.ID); !ok || got.Challenge != r.Challenge {
		t.Fatalf("after a restart %+v", got)
	}
	if list := f.svc.List(); len(list) != 1 {
		t.Fatalf("list %v", list)
	}
}
