// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/sys/unix"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootshell"
)

func (b *box) elevationAs(uid uint32, fp string) accessv1connect.ElevationServiceClient {
	hc, url := b.as(uid)
	if fp == "" {
		return accessv1connect.NewElevationServiceClient(hc, url)
	}
	return accessv1connect.NewElevationServiceClient(hc, url, connect.WithInterceptors(keyHeader(fp)))
}

func (b *box) shellElevation(name string) accessv1connect.ElevationServiceClient {
	return b.elevationAs(b.uids[name], b.keys[name].fp)
}

// signIn signs name in on :8443 through the osadmin uid and returns the
// cookie and the CSRF token.
func (b *box) signIn(name string) (string, string) {
	b.t.Helper()
	hc, url := b.osadmin()
	req := connect.NewRequest(&osadminv1.SignInRequest{Admin: name, Password: testPassword, TotpCode: b.code(name)})
	req.Header().Set(accessapi.ClientHeader, "203.0.113.9")
	out, err := osadminv1connect.NewSignInServiceClient(hc, url).SignIn(context.Background(), req)
	if err != nil {
		b.t.Fatal(err)
	}
	ck, err := http.ParseSetCookie(out.Header().Get("Set-Cookie"))
	if err != nil {
		b.t.Fatal(err)
	}
	return ck.Name + "=" + ck.Value, out.Msg.GetSession().GetCsrfToken()
}

func withSession[T any](r *connect.Request[T], cookie, csrf string) *connect.Request[T] {
	r.Header().Set("Cookie", cookie)
	r.Header().Set(osadmin.CSRFHeader, csrf)
	return r
}

// The root shell through access.sock: alice's shell gets a challenge, her
// :8443 session gets the code with a fresh TOTP code, the shell trades
// both for a ticket, and sneakers-elevated (root) uses the ticket up and
// reports the end. Each step is audited.
func TestTheRootShellEndToEnd(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	alice := b.shellElevation("alice")
	ch, err := alice.BeginRootShell(ctx, connect.NewRequest(&accessv1.BeginRootShellRequest{Reason: "investigate kubelet"}))
	if err != nil {
		t.Fatal(err)
	}
	if ch.Msg.GetUrl() != "https://192.0.2.10:8443/root-shell" || len(ch.Msg.GetChallenge()) != 19 {
		t.Fatalf("challenge %v", ch.Msg)
	}
	if e := lastEntry(t, b.log, "rootshell.challenge"); e.Actor != "alice" || e.Source != "192.0.2.50" || e.KeyFP != b.keys["alice"].fp {
		t.Fatalf("audit %+v", e)
	}
	cookie, csrf := b.signIn("alice")
	hc, url := b.osadmin()
	code, err := osadminv1connect.NewRootShellServiceClient(hc, url).IssueRootShellCode(ctx, withSession(connect.NewRequest(&osadminv1.IssueRootShellCodeRequest{Challenge: ch.Msg.GetChallenge(), TotpCode: b.code("alice")}), cookie, csrf))
	if err != nil {
		t.Fatal(err)
	}
	_, err = alice.OpenRootShell(ctx, connect.NewRequest(&accessv1.OpenRootShellRequest{Challenge: ch.Msg.GetChallenge(), Code: "0000-0000"}))
	if err == nil || !strings.Contains(err.Error(), "ROOT_CODE") {
		t.Fatalf("a wrong code: %v", err)
	}
	open, err := alice.OpenRootShell(ctx, connect.NewRequest(&accessv1.OpenRootShellRequest{Challenge: ch.Msg.GetChallenge(), Code: code.Msg.GetCode()}))
	if err != nil {
		t.Fatal(err)
	}
	if open.Msg.GetTicket() == "" || open.Msg.GetSocket() != filepath.Join(b.run, "rootshell.sock") || open.Msg.GetSessionMinutes() != 10 {
		t.Fatalf("open %v", open.Msg)
	}
	console := b.elevationAs(0, "")
	if _, err := console.BeginElevatedSession(ctx, connect.NewRequest(&accessv1.BeginElevatedSessionRequest{Ticket: open.Msg.GetTicket(), Admin: "bob", Pid: 9})); err == nil {
		t.Fatal("alice's ticket opened a shell for bob")
	}
	begin, err := console.BeginElevatedSession(ctx, connect.NewRequest(&accessv1.BeginElevatedSessionRequest{Ticket: open.Msg.GetTicket(), Admin: "alice", Pid: 9}))
	if err != nil || begin.Msg.GetElevation().GetState() != "active" {
		t.Fatalf("begin %v %v", begin, err)
	}
	if _, err := console.EndElevatedSession(ctx, connect.NewRequest(&accessv1.EndElevatedSessionRequest{Id: begin.Msg.GetElevation().GetId(), Reason: "idle", RecordingSha256: "abc"})); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, b.log, "rootshell.end"); e.Outcome != "idle" {
		t.Fatalf("audit %+v", e)
	}
}

// The console has no SSH login to tie a challenge to, and an admin who
// isn't a root operator gets none.
func TestOnlyARootOperatorsLoginGetsAChallenge(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	_, err := b.elevationAs(0, "").BeginRootShell(ctx, connect.NewRequest(&accessv1.BeginRootShellRequest{}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	if err := b.store.Update(func(st *access.State) error {
		st.Quorum = &access.QuorumRoster{Members: []string{"alice"}, Required: 1}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err = b.shellElevation("bob").BeginRootShell(ctx, connect.NewRequest(&accessv1.BeginRootShellRequest{}))
	if err == nil || !strings.Contains(err.Error(), "ACCESS_FORBIDDEN") {
		t.Fatalf("bob got a challenge: %v", err)
	}
}

// socketpair returns both ends of a unix stream socket pair.
func socketpair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "socketpair") // #nosec G115 -- a descriptor
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	return conn(fds[0]), conn(fds[1])
}

// A root-shell connection runs sneakers-elevated with the connection as
// its terminal: the ticket and the admin of the connection's uid come in
// its environment, and what the client sends after the handshake reaches
// it.
func TestARootShellConnectionRunsElevated(t *testing.T) {
	b := newBox(t)
	script := filepath.Join(t.TempDir(), "elevated")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho \"ticket=$SNEAKERS_ROOT_TICKET admin=$SNEAKERS_ROOT_ADMIN rows=$SNEAKERS_ROOT_ROWS cols=$SNEAKERS_ROOT_COLS\"\nhead -c 9\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	d := accessd.New(accessd.Options{Elevated: script, Paths: accessd.Paths{Run: t.TempDir()}})
	d.Attach(b.store, b.api)
	server, client := socketpair(t)
	done := make(chan struct{})
	go func() {
		d.RootShellConn(context.Background(), server, b.uids["bob"])
		close(done)
	}()
	if err := rootshell.WriteHandshake(client, rootshell.Handshake{Ticket: "tkt", Term: "xterm", Rows: 30, Cols: 100}); err != nil {
		t.Fatal(err)
	}
	if err := rootshell.WriteData(client, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	_ = client.CloseWrite()
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	out, _ := io.ReadAll(client)
	if !strings.Contains(string(out), "ticket=tkt admin=bob rows=30 cols=100") {
		t.Fatalf("out %q", out)
	}
	if !strings.Contains(string(out), "hi") {
		t.Fatalf("the typed bytes didn't reach it: %q", out)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the connection wasn't closed")
	}
}

// A connection from a uid with no admin behind it runs nothing.
func TestARootShellConnectionFromNoAdminRunsNothing(t *testing.T) {
	b := newBox(t)
	marker := filepath.Join(t.TempDir(), "ran")
	script := filepath.Join(t.TempDir(), "elevated")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	d := accessd.New(accessd.Options{Elevated: script, Paths: accessd.Paths{Run: t.TempDir()}})
	d.Attach(b.store, b.api)
	server, client := socketpair(t)
	go func() { _ = rootshell.WriteHandshake(client, rootshell.Handshake{Ticket: "tkt"}) }()
	d.RootShellConn(context.Background(), server, 20099)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("sneakers-elevated ran for a uid with no admin")
	}
}

func TestARecordingIsReadAndVerified(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	st := b.store.Read()
	c := elevation.Caller{Admin: "bob", KeyFP: b.keys["bob"].fp, Source: "192.0.2.50"}
	r, err := b.elev.Challenge(st, c, "x")
	if err != nil {
		t.Fatal(err)
	}
	_, code, err := b.elev.IssueCode(st, "bob", r.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	_, ticket, err := b.elev.Open(st, c, r.Challenge, code)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.elev.Begin(ticket, "bob", 7); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(osaudit.RecordingPath(b.log.Dir(), r.ID)) // #nosec G304 -- test path
	if err != nil {
		t.Fatal(err)
	}
	rec := osaudit.NewRecorder(f, b.log, r.ID)
	_, _ = rec.Write([]byte("# id\r\nuid=0(root)\r\n"))
	if err := rec.Close("exit"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	cookie, csrf := b.signIn("alice")
	hc, url := b.osadmin()
	got, err := osadminv1connect.NewElevationServiceClient(hc, url).GetElevationRecording(ctx, withSession(connect.NewRequest(&osadminv1.GetElevationRecordingRequest{Id: r.ID}), cookie, csrf))
	if err != nil || !got.Msg.GetVerified() || !strings.Contains(string(got.Msg.GetCast()), "uid=0(root)") {
		t.Fatalf("%v %v", got, err)
	}
	bcookie, bcsrf := b.signIn("bob")
	_, err = osadminv1connect.NewElevationServiceClient(hc, url).GetElevationRecording(ctx, withSession(connect.NewRequest(&osadminv1.GetElevationRecordingRequest{Id: r.ID}), bcookie, bcsrf))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}
