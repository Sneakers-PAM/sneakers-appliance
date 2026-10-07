// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
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

func (b *box) principals() string {
	b.t.Helper()
	got, err := os.ReadFile(filepath.Join(b.run, "ssh", "principals", "maint"))
	if err != nil {
		b.t.Fatal(err)
	}
	return string(got)
}

// The whole elevation through access.sock: bob's shell asks, the console
// shortens and approves, bob fetches the certificate, sneakers-elevated
// (root) uses it up and reports the end. Each step is audited.
func TestElevationEndToEnd(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	bob := b.shellElevation("bob")
	req, err := bob.RequestElevation(ctx, connect.NewRequest(&accessv1.RequestElevationRequest{Minutes: 30, Reason: "investigate kubelet"}))
	if err != nil {
		t.Fatal(err)
	}
	e := req.Msg.GetElevation()
	id := e.GetId()
	if e.GetState() != "pending" || e.GetAdmin() != "bob" || e.GetKeyFingerprint() != b.keys["bob"].fp || e.GetSourceAddress() != "192.0.2.50" {
		t.Fatalf("%v", e)
	}
	if en := lastEntry(t, b.log, "elevation.request"); en.Actor != "bob" || en.Target != id || en.Source != "192.0.2.50" {
		t.Fatalf("%+v", en)
	}
	_, err = bob.ApproveElevation(ctx, connect.NewRequest(&accessv1.ApproveElevationRequest{Id: id}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	_, err = bob.GetElevationCertificate(ctx, connect.NewRequest(&accessv1.GetElevationCertificateRequest{Id: id}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ELEV_UNKNOWN")

	console := b.elevationAs(0, "")
	if _, err := console.ApproveElevation(ctx, connect.NewRequest(&accessv1.ApproveElevationRequest{Id: id, Minutes: 20})); err != nil {
		t.Fatal(err)
	}
	if en := lastEntry(t, b.log, "elevation.approve"); en.Actor != "console" || en.Outcome != "ok" || en.Target != id || en.Detail["minutes"] != "20" {
		t.Fatalf("%+v", en)
	}
	if got := b.principals(); got != "elev-"+id+"\n" {
		t.Fatalf("principals %q", got)
	}

	_, err = b.shellElevation("alice").GetElevationCertificate(ctx, connect.NewRequest(&accessv1.GetElevationCertificateRequest{Id: id}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ELEV_UNKNOWN")
	cert, err := bob.GetElevationCertificate(ctx, connect.NewRequest(&accessv1.GetElevationCertificateRequest{Id: id}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cert.Msg.GetLogin(), "maint@192.0.2.10") {
		t.Fatalf("login %q", cert.Msg.GetLogin())
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cert.Msg.GetCertificate()))
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := pk.(*ssh.Certificate); !ok || !slices.Equal(c.ValidPrincipals, []string{"elev-" + id}) {
		t.Fatalf("%v", pk)
	}

	_, err = bob.BeginElevatedSession(ctx, connect.NewRequest(&accessv1.BeginElevatedSessionRequest{Certificate: cert.Msg.GetCertificate(), Pid: 4242}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	begin, err := console.BeginElevatedSession(ctx, connect.NewRequest(&accessv1.BeginElevatedSessionRequest{Certificate: cert.Msg.GetCertificate(), Pid: 4242}))
	if err != nil {
		t.Fatal(err)
	}
	if begin.Msg.GetElevation().GetMinutes() != 20 || begin.Msg.GetElevation().GetState() != "active" ||
		begin.Msg.GetEnds().AsTime().Sub(begin.Msg.GetElevation().GetStarted().AsTime()).Minutes() != 20 {
		t.Fatalf("%v", begin.Msg)
	}
	if got := b.principals(); got != "" {
		t.Fatalf("the used principal is still open: %q", got)
	}
	if _, err := os.Stat(filepath.Join(b.state, "ssh", elevation.RevokedFile)); err != nil {
		t.Fatal(err)
	}
	_, err = console.BeginElevatedSession(ctx, connect.NewRequest(&accessv1.BeginElevatedSessionRequest{Certificate: cert.Msg.GetCertificate(), Pid: 4243}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ELEV_USED")
	if en := lastEntry(t, b.log, "elevation.connect"); en.Outcome != "refused" || en.Code != "ELEV_USED" {
		t.Fatalf("%+v", en)
	}

	if _, err := console.TerminateElevation(ctx, connect.NewRequest(&accessv1.TerminateElevationRequest{Id: id})); err != nil {
		t.Fatal(err)
	}
	if got := b.signalled(); !slices.Equal(got, []int{4242}) {
		t.Fatalf("signals %v", got)
	}
	if _, err := console.EndElevatedSession(ctx, connect.NewRequest(&accessv1.EndElevatedSessionRequest{Id: id, Reason: "terminated", RecordingSha256: "ab12"})); err != nil {
		t.Fatal(err)
	}
	if en := lastEntry(t, b.log, "elevation.end"); en.Outcome != "terminated" || en.Detail["recordingSha256"] != "ab12" {
		t.Fatalf("%+v", en)
	}
	list, err := bob.ListElevations(ctx, connect.NewRequest(&accessv1.ListElevationsRequest{}))
	if err != nil || len(list.Msg.GetElevations()) != 1 || list.Msg.GetElevations()[0].GetEndReason() != "terminated" {
		t.Fatalf("%v %v", list, err)
	}
}

// The console has no key to sign, so it can't ask for elevation.
func TestTheConsoleCantRequestElevation(t *testing.T) {
	b := newBox(t)
	_, err := b.elevationAs(0, "").RequestElevation(context.Background(), connect.NewRequest(&accessv1.RequestElevationRequest{Minutes: 30, Reason: "x"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}

// signIn signs name in to :8443 through accessd and returns the cookie
// and CSRF token.
func (b *box) signIn(name string) (string, string) {
	b.t.Helper()
	ctx := context.Background()
	hc, url := b.osadmin()
	si := osadminv1connect.NewSignInServiceClient(hc, url)
	begin := connect.NewRequest(&osadminv1.BeginSignInRequest{})
	begin.Header().Set(accessapi.ClientHeader, "203.0.113.9")
	code, err := si.BeginSignIn(ctx, begin)
	if err != nil {
		b.t.Fatal(err)
	}
	shc, surl := b.as(b.uids[name])
	if _, err := osadminv1connect.NewLocalServiceClient(shc, surl).ApproveSignIn(ctx, connect.NewRequest(&osadminv1.ApproveSignInRequest{Code: code.Msg.GetCode(), Admin: name, KeyFingerprint: b.keys[name].fp})); err != nil {
		b.t.Fatal(err)
	}
	poll, err := si.PollSignIn(ctx, connect.NewRequest(&osadminv1.PollSignInRequest{PollToken: code.Msg.GetPollToken()}))
	if err != nil {
		b.t.Fatal(err)
	}
	ck, err := http.ParseSetCookie(poll.Header().Get("Set-Cookie"))
	if err != nil {
		b.t.Fatal(err)
	}
	return ck.Name + "=" + ck.Value, poll.Msg.GetSession().GetCsrfToken()
}

func withSession[T any](r *connect.Request[T], cookie, csrf string) *connect.Request[T] {
	r.Header().Set("Cookie", cookie)
	r.Header().Set(osadmin.CSRFHeader, csrf)
	return r
}

// The only owner may approve their own request on :8443; it's flagged on
// the request, in the audit entry and on Status. With a second owner, it
// is refused.
func TestSelfApprovalOn8443(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	req, err := b.shellElevation("alice").RequestElevation(ctx, connect.NewRequest(&accessv1.RequestElevationRequest{Minutes: 30, Reason: "kubelet"}))
	if err != nil {
		t.Fatal(err)
	}
	id := req.Msg.GetElevation().GetId()
	cookie, csrf := b.signIn("alice")
	hc, url := b.osadmin()
	el := osadminv1connect.NewElevationServiceClient(hc, url)
	if _, err := el.ApproveElevation(ctx, withSession(connect.NewRequest(&osadminv1.ApproveElevationRequest{Id: id}), cookie, csrf)); err != nil {
		t.Fatal(err)
	}
	if en := lastEntry(t, b.log, "elevation.approve"); en.Actor != "alice" || en.Detail["selfApproved"] != "true" || en.Detail["surface"] != "8443" {
		t.Fatalf("%+v", en)
	}
	list, err := el.ListElevations(ctx, withSession(connect.NewRequest(&osadminv1.ListElevationsRequest{}), cookie, csrf))
	if err != nil || !list.Msg.GetElevations()[0].GetSelfApproved() {
		t.Fatalf("%v %v", list, err)
	}
	st, err := osadminv1connect.NewStatusServiceClient(hc, url).GetStatus(ctx, withSession(connect.NewRequest(&osadminv1.GetStatusRequest{}), cookie, csrf))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(st.Msg.GetWarnings(), func(w *osadminv1.Warning) bool {
		return w.GetKind() == osadminv1.WarningKind_WARNING_KIND_SELF_APPROVED_ELEVATION
	}) {
		t.Fatalf("no self-approved warning: %v", st.Msg.GetWarnings())
	}

	b.addAdmin("carol", access.RoleOwner)
	req2, err := b.shellElevation("alice").RequestElevation(ctx, connect.NewRequest(&accessv1.RequestElevationRequest{Minutes: 30, Reason: "kubelet"}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = el.ApproveElevation(ctx, withSession(connect.NewRequest(&osadminv1.ApproveElevationRequest{Id: req2.Msg.GetElevation().GetId()}), cookie, csrf))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ELEV_SELF_APPROVAL")
	ccookie, ccsrf := b.signIn("carol")
	if _, err := el.DenyElevation(ctx, withSession(connect.NewRequest(&osadminv1.DenyElevationRequest{Id: req2.Msg.GetElevation().GetId()}), ccookie, ccsrf)); err != nil {
		t.Fatal(err)
	}
	if en := lastEntry(t, b.log, "elevation.deny"); en.Actor != "carol" || en.Outcome != "ok" {
		t.Fatalf("%+v", en)
	}
}

// An admin (not an owner) can't approve on :8443.
func TestAnAdminCantApproveOn8443(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	req, err := b.shellElevation("bob").RequestElevation(ctx, connect.NewRequest(&accessv1.RequestElevationRequest{Minutes: 30, Reason: "x"}))
	if err != nil {
		t.Fatal(err)
	}
	cookie, csrf := b.signIn("bob")
	hc, url := b.osadmin()
	_, err = osadminv1connect.NewElevationServiceClient(hc, url).ApproveElevation(ctx, withSession(connect.NewRequest(&osadminv1.ApproveElevationRequest{Id: req.Msg.GetElevation().GetId()}), cookie, csrf))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}

// Owners read a session's recording, checked against the audit log's
// chunk hashes.
func TestARecordingIsReadAndVerified(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	req, err := b.shellElevation("bob").RequestElevation(ctx, connect.NewRequest(&accessv1.RequestElevationRequest{Minutes: 30, Reason: "x"}))
	if err != nil {
		t.Fatal(err)
	}
	id := req.Msg.GetElevation().GetId()
	console := b.elevationAs(0, "")
	if _, err := console.ApproveElevation(ctx, connect.NewRequest(&accessv1.ApproveElevationRequest{Id: id})); err != nil {
		t.Fatal(err)
	}
	cert, err := b.shellElevation("bob").GetElevationCertificate(ctx, connect.NewRequest(&accessv1.GetElevationCertificateRequest{Id: id}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := console.BeginElevatedSession(ctx, connect.NewRequest(&accessv1.BeginElevatedSessionRequest{Certificate: cert.Msg.GetCertificate(), Pid: 7})); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(osaudit.RecordingPath(b.log.Dir(), id)) // #nosec G304 -- test path
	if err != nil {
		t.Fatal(err)
	}
	rec := osaudit.NewRecorder(f, b.log, id)
	_, _ = rec.Write([]byte("# id\r\nuid=0(root)\r\n"))
	if err := rec.Close("exit"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	cookie, csrf := b.signIn("alice")
	hc, url := b.osadmin()
	got, err := osadminv1connect.NewElevationServiceClient(hc, url).GetElevationRecording(ctx, withSession(connect.NewRequest(&osadminv1.GetElevationRecordingRequest{Id: id}), cookie, csrf))
	if err != nil || !got.Msg.GetVerified() || !strings.Contains(string(got.Msg.GetCast()), "uid=0(root)") {
		t.Fatalf("%v %v", got, err)
	}
	bcookie, bcsrf := b.signIn("bob")
	_, err = osadminv1connect.NewElevationServiceClient(hc, url).GetElevationRecording(ctx, withSession(connect.NewRequest(&osadminv1.GetElevationRecordingRequest{Id: id}), bcookie, bcsrf))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}
