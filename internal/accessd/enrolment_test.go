// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accounts"
)

func (b *box) read(rel string) string {
	b.t.Helper()
	got, err := os.ReadFile(filepath.Join(b.run, rel))
	if err != nil {
		b.t.Fatal(err)
	}
	return string(got)
}

func TestTheEnrolUIDIsAPeer(t *testing.T) {
	if !accessd.PeerAllowed(accounts.EnrolUID) {
		t.Fatal("the enrol uid is refused")
	}
}

// The window as the design runs it: the console opens it (host keys made,
// the enrol account and sshd's enrol block rendered), sneakers-enrol sends
// the code and its key, the console's yes stores the key, Done closes the
// window and the enrol account goes away.
func TestTheEnrolmentWindow(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	if strings.Contains(b.read("accounts/passwd"), "enrol:") || strings.Contains(b.read("ssh/sshd_config"), "Match User enrol") {
		t.Fatal("the enrol account exists outside a window")
	}
	chc, curl := b.console()
	console := accessv1connect.NewEnrolmentServiceClient(chc, curl)
	open, err := console.OpenEnrolment(ctx, connect.NewRequest(&accessv1.OpenEnrolmentRequest{Admin: "alice"}))
	if err != nil {
		t.Fatal(err)
	}
	w := open.Msg.GetEnrolment()
	if !w.GetOpen() || len(w.GetCode()) != 9 || w.GetAttemptsLeft() != 3 || len(w.GetHostKeys()) != 2 {
		t.Fatalf("%v", w)
	}
	for _, k := range []string{"ssh_host_ed25519_key", "ssh_host_rsa_key"} {
		fi, err := os.Stat(filepath.Join(b.state, "ssh", k))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", k, fi, err)
		}
	}
	if !strings.Contains(b.read("accounts/passwd"), "enrol:x:103:") || !strings.Contains(b.read("ssh/sshd_config"), "Match User enrol") {
		t.Fatal("the window didn't render the enrol account")
	}

	ehc, eurl := b.as(accounts.EnrolUID)
	session := accessv1connect.NewEnrolmentServiceClient(ehc, eurl, connect.WithInterceptors(keyHeader("")))
	k := newKey(t)
	_, err = session.SubmitEnrolmentCode(ctx, connect.NewRequest(&accessv1.SubmitEnrolmentCodeRequest{Code: "ZZZZ-ZZZZ", PublicKey: k.line}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ENROL_CODE")
	sub, err := session.SubmitEnrolmentCode(ctx, connect.NewRequest(&accessv1.SubmitEnrolmentCodeRequest{Code: w.GetCode(), PublicKey: k.line}))
	if err != nil || sub.Msg.GetAdmin() != "alice" || sub.Msg.GetFingerprint() != k.fp {
		t.Fatalf("%v %v", sub, err)
	}
	if en := lastEntry(t, b.log, "enrol.submit"); en.Source != "192.0.2.50" || en.KeyFP != k.fp {
		t.Fatalf("%+v", en)
	}
	got, err := session.GetEnrolmentKey(ctx, connect.NewRequest(&accessv1.GetEnrolmentKeyRequest{Id: sub.Msg.GetId()}))
	if err != nil || got.Msg.GetKey().GetState() != "waiting" {
		t.Fatalf("%v %v", got, err)
	}
	_, err = session.OpenEnrolment(ctx, connect.NewRequest(&accessv1.OpenEnrolmentRequest{Admin: "bob"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	_, err = session.AcceptEnrolmentKey(ctx, connect.NewRequest(&accessv1.AcceptEnrolmentKeyRequest{Id: sub.Msg.GetId(), Confirm: "yes"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	if _, err := accessv1connect.NewAccessServiceClient(ehc, eurl).ListAdmins(ctx, connect.NewRequest(&accessv1.ListAdminsRequest{})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("the enrol uid reached the access service: %v", err)
	}
	_, err = b.shellEnrolment("alice").SubmitEnrolmentCode(ctx, connect.NewRequest(&accessv1.SubmitEnrolmentCodeRequest{Code: w.GetCode(), PublicKey: k.line}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")

	if _, err := console.AcceptEnrolmentKey(ctx, connect.NewRequest(&accessv1.AcceptEnrolmentKeyRequest{Id: sub.Msg.GetId(), Confirm: "yes"})); err != nil {
		t.Fatal(err)
	}
	st := b.store.Read()
	a, _ := st.Admin("alice")
	if len(a.Keys) != 2 || a.Keys[1].Fingerprint != k.fp || a.Keys[1].Via != "enrol" {
		t.Fatalf("%+v", a.Keys)
	}
	got, err = session.GetEnrolmentKey(ctx, connect.NewRequest(&accessv1.GetEnrolmentKeyRequest{Id: sub.Msg.GetId()}))
	if err != nil || got.Msg.GetKey().GetState() != "accepted" {
		t.Fatalf("%v %v", got, err)
	}
	if !strings.Contains(b.read("ssh/authorized_keys/alice"), strings.Fields(k.line)[1]) {
		t.Fatal("the stored key isn't in alice's authorized keys")
	}
	if _, err := console.CloseEnrolment(ctx, connect.NewRequest(&accessv1.CloseEnrolmentRequest{})); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.read("accounts/passwd"), "enrol:") || strings.Contains(b.read("ssh/sshd_config"), "Match User enrol") {
		t.Fatal("the enrol account outlived the window")
	}
	if en := lastEntry(t, b.log, "enrol.close"); en.Outcome != "done" {
		t.Fatalf("%+v", en)
	}
	_, err = session.SubmitEnrolmentCode(ctx, connect.NewRequest(&accessv1.SubmitEnrolmentCodeRequest{Code: w.GetCode(), PublicKey: k.line}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ENROL_CLOSED")
}

func (b *box) shellEnrolment(name string) accessv1connect.EnrolmentServiceClient {
	hc, url := b.as(b.uids[name])
	return accessv1connect.NewEnrolmentServiceClient(hc, url, connect.WithInterceptors(keyHeader(b.keys[name].fp)))
}
