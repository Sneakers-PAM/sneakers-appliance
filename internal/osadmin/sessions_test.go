// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshsession"
)

// fakeShells is the box's SSH closed shells.
type fakeShells struct {
	mu      sync.Mutex
	live    []sshsession.Session
	sources map[int]string
	ended   []string
}

func (f *fakeShells) List() ([]sshsession.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sshsession.Session(nil), f.live...), nil
}

func (f *fakeShells) End(id string) (sshsession.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, s := range f.live {
		if s.ID == id {
			f.live = append(f.live[:i], f.live[i+1:]...)
			f.ended = append(f.ended, id)
			return s, nil
		}
	}
	return sshsession.Session{}, sshsession.ErrNotFound
}

func (f *fakeShells) Source(pid int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sources[pid]
}

func (b *box) sshLogin(admin, source string, pid int) sshsession.Session {
	s := sshsession.Session{ID: "ssh-" + strconv.Itoa(pid) + "-1", PID: pid, Admin: admin, Source: source, Started: b.clk.Now()}
	b.shells.mu.Lock()
	b.shells.live = append(b.shells.live, s)
	b.shells.mu.Unlock()
	return s
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func listSessions(t *testing.T, br *browser) []*osadminv1.ActiveSession {
	t.Helper()
	r, err := br.power().ListSessions(context.Background(), connect.NewRequest(&osadminv1.ListSessionsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return r.Msg.GetSessions()
}

func byKind(ss []*osadminv1.ActiveSession, k osadminv1.SessionKind) []*osadminv1.ActiveSession {
	var out []*osadminv1.ActiveSession
	for _, s := range ss {
		if s.GetKind() == k {
			out = append(out, s)
		}
	}
	return out
}

func TestListSessionsShowsEveryKindOfSession(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	b.clk.Advance(time.Minute)
	b.sshLogin("bob", "192.0.2.80", 700)
	b.clk.Advance(time.Minute)
	elev := b.elevated()
	b.shells.sources = map[int]string{4242: "192.0.2.81"}

	got := listSessions(t, alice)
	if len(got) != 3 {
		t.Fatalf("sessions %v", got)
	}
	web, ssh, root := got[0], got[1], got[2]
	if web.GetKind() != osadminv1.SessionKind_SESSION_KIND_BROWSER || web.GetAdmin() != "alice" || web.GetSourceAddress() == "" || web.GetId() == "" {
		t.Fatalf("browser %v", web)
	}
	if ssh.GetKind() != osadminv1.SessionKind_SESSION_KIND_SSH || ssh.GetAdmin() != "bob" || ssh.GetSourceAddress() != "192.0.2.80" || ssh.GetId() != "ssh-700-1" {
		t.Fatalf("ssh %v", ssh)
	}
	if root.GetKind() != osadminv1.SessionKind_SESSION_KIND_ELEVATED || root.GetAdmin() != "bob" || root.GetSourceAddress() != "192.0.2.81" || !strings.Contains(root.GetId(), elev.ID) {
		t.Fatalf("elevated %v", root)
	}
	if !web.GetSignedIn().AsTime().Before(ssh.GetSignedIn().AsTime()) {
		t.Fatal("not oldest first")
	}
	// The id never carries the browser's session cookie.
	for _, c := range alice.hc.Jar.Cookies(mustURL(t, b.ts.URL)) {
		if strings.Contains(web.GetId(), c.Value) {
			t.Fatal("the id is the cookie")
		}
	}
	// The graceful shutdown warning lists the same sessions.
	gp, err := alice.power().GetPower(context.Background(), connect.NewRequest(&osadminv1.GetPowerRequest{}))
	if err != nil || len(gp.Msg.GetSessions()) != 3 {
		t.Fatalf("GetPower %v %v", gp, err)
	}
}

func TestListSessionsLeavesOutEndedSessions(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	bob := b.browser()
	bob.signIn("bob")
	si := osadminv1connect.NewSignInServiceClient(bob.hc, b.ts.URL)
	if _, err := si.SignOut(context.Background(), connect.NewRequest(&osadminv1.SignOutRequest{})); err != nil {
		t.Fatal(err)
	}
	if got := listSessions(t, alice); len(got) != 1 || got[0].GetAdmin() != "alice" {
		t.Fatalf("sessions %v", got)
	}
}

func TestAnOwnerEndsABrowserSession(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	bob := b.browser()
	bob.signIn("bob")
	target := byKind(listSessions(t, alice), osadminv1.SessionKind_SESSION_KIND_BROWSER)
	var bobs *osadminv1.ActiveSession
	for _, s := range target {
		if s.GetAdmin() == "bob" {
			bobs = s
		}
	}
	if bobs == nil {
		t.Fatal("bob's session isn't listed")
	}
	if _, err := alice.power().EndSession(context.Background(), connect.NewRequest(&osadminv1.EndSessionRequest{Id: bobs.GetId()})); err != nil {
		t.Fatal(err)
	}
	_, err := bob.power().ListSessions(context.Background(), connect.NewRequest(&osadminv1.ListSessionsRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("bob is still signed in: %v", err)
	}
	if got := listSessions(t, alice); len(got) != 1 || got[0].GetAdmin() != "alice" {
		t.Fatalf("sessions %v", got)
	}
	e := lastEntry(t, b.log, "session.end")
	if e.Actor != "alice" || e.Target != "bob's browser session from 127.0.0.1" || e.Detail["session"] != bobs.GetId() || e.Detail["kind"] != "browser" || e.Detail["admin"] != "bob" {
		t.Fatalf("audit %+v", e)
	}
}

func TestAnOwnerEndsAnSSHSession(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	s := b.sshLogin("bob", "192.0.2.80", 700)
	if _, err := alice.power().EndSession(context.Background(), connect.NewRequest(&osadminv1.EndSessionRequest{Id: s.ID})); err != nil {
		t.Fatal(err)
	}
	if len(b.shells.ended) != 1 || b.shells.ended[0] != s.ID {
		t.Fatalf("ended %v", b.shells.ended)
	}
	if got := byKind(listSessions(t, alice), osadminv1.SessionKind_SESSION_KIND_SSH); len(got) != 0 {
		t.Fatalf("still listed %v", got)
	}
	e := lastEntry(t, b.log, "session.end")
	if e.Detail["kind"] != "ssh" || e.Detail["admin"] != "bob" || e.Detail["source"] != "192.0.2.80" {
		t.Fatalf("audit %+v", e)
	}
}

func TestAnOwnerEndsAnElevatedShell(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	b.elevated()
	root := byKind(listSessions(t, alice), osadminv1.SessionKind_SESSION_KIND_ELEVATED)
	if len(root) != 1 {
		t.Fatalf("elevated %v", root)
	}
	if _, err := alice.power().EndSession(context.Background(), connect.NewRequest(&osadminv1.EndSessionRequest{Id: root[0].GetId()})); err != nil {
		t.Fatal(err)
	}
	if len(b.signals) != 1 || b.signals[0] != 4242 {
		t.Fatalf("signals %v", b.signals)
	}
}

func TestEndSessionNeedsAnOwnerButNoCode(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	bob := b.browser()
	bob.signIn("bob")
	s := b.sshLogin("alice", "192.0.2.80", 700)
	ctx := context.Background()
	_, err := bob.power().EndSession(ctx, connect.NewRequest(&osadminv1.EndSessionRequest{Id: s.ID}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("an admin ended a session: %v", err)
	}
	if len(b.shells.ended) != 0 {
		t.Fatalf("ended %v", b.shells.ended)
	}
	b.clk.Advance(6 * time.Minute)
	if _, err := alice.power().EndSession(ctx, connect.NewRequest(&osadminv1.EndSessionRequest{Id: s.ID})); err != nil {
		t.Fatalf("an owner ends a session outside the step-up window: %v", err)
	}
	if len(b.shells.ended) != 1 {
		t.Fatalf("ended %v", b.shells.ended)
	}
}

func TestEndSessionRefusesAnUnknownID(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	b.elevated()
	for _, id := range []string{"", "web-0000", "ssh-1-1", "elevated-nope", "other"} {
		_, err := alice.power().EndSession(context.Background(), connect.NewRequest(&osadminv1.EndSessionRequest{Id: id}))
		if connect.CodeOf(err) != connect.CodeNotFound {
			t.Errorf("EndSession(%q) = %v", id, err)
		}
	}
	if len(b.signals) != 0 {
		t.Fatalf("signals %v", b.signals)
	}
}
