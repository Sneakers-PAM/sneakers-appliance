// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

// Once setup is done the setup-only calls are refused with SETUP_DONE,
// from the rules table, and audited; the recovery keys stay an owner's.
func TestTheSetupOnlyCallsAreRefusedOnceSetupIsDone(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	su := setupClient(alice)
	if _, err := su.AddRecoveryKey(ctx, connect.NewRequest(&osadminv1.AddRecoveryKeyRequest{PublicKey: newKey(t).line})); err != nil {
		t.Fatal(err)
	}
	b.finishSetup()

	_, err := su.AcknowledgeStep(ctx, connect.NewRequest(&osadminv1.AcknowledgeStepRequest{Step: osadminv1.SetupStepKind_SETUP_STEP_KIND_NETWORK}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_DONE")
	if e := lastEntry(t, b.log, "setup.step.acknowledge"); e.Outcome != "refused" || e.Code != "SETUP_DONE" || e.Actor != "alice" {
		t.Fatalf("%+v", e)
	}
	_, err = su.AcknowledgeSingleAdmin(ctx, connect.NewRequest(&osadminv1.AcknowledgeSingleAdminRequest{}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_DONE")
	if e := lastEntry(t, b.log, "setup.single-admin.acknowledge"); e.Outcome != "refused" || e.Code != "SETUP_DONE" {
		t.Fatalf("%+v", e)
	}
	_, err = su.Finish(ctx, connect.NewRequest(&osadminv1.FinishRequest{}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_DONE")
	if e := lastEntry(t, b.log, "setup.finish"); e.Outcome != "refused" || e.Code != "SETUP_DONE" {
		t.Fatalf("%+v", e)
	}

	if _, err := su.AddRecoveryKey(ctx, connect.NewRequest(&osadminv1.AddRecoveryKeyRequest{PublicKey: newKey(t).line})); err != nil {
		t.Fatalf("the recovery keys stay available: %v", err)
	}
	if _, err := su.DownloadEscrow(ctx, connect.NewRequest(&osadminv1.DownloadEscrowRequest{})); err != nil {
		t.Fatalf("the escrow stays available: %v", err)
	}
	g, err := su.GetSetup(ctx, connect.NewRequest(&osadminv1.GetSetupRequest{}))
	if err != nil || !g.Msg.GetDone() {
		t.Fatalf("an admin still reads setup: %v %v", g, err)
	}
}

// A setup code session left open when setup finished can't go on: every
// call it makes is refused.
func TestASetupCodeSessionEndsWithSetup(t *testing.T) {
	b := newFreshBox(t)
	ctx := context.Background()
	br := b.browser()
	su := setupClient(br)
	red, err := su.RedeemCode(ctx, connect.NewRequest(&osadminv1.RedeemCodeRequest{Code: b.console().GetSetupCode()}))
	if err != nil {
		t.Fatal(err)
	}
	br.csrf = red.Msg.GetCsrfToken()
	b.finishSetup()

	_, err = su.GetSetup(ctx, connect.NewRequest(&osadminv1.GetSetupRequest{}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_DONE")
	_, err = su.CheckPassword(ctx, connect.NewRequest(&osadminv1.CheckPasswordRequest{Password: testPassword}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_DONE")
	_, err = su.BeginCredentials(ctx, connect.NewRequest(&osadminv1.BeginCredentialsRequest{Admin: "mallory", Password: testPassword}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_DONE")
	if e := lastEntry(t, b.log, "setup.credentials.begin"); e.Outcome != "refused" || e.Code != "SETUP_DONE" {
		t.Fatalf("%+v", e)
	}
	_, err = su.CompleteCredentials(ctx, connect.NewRequest(&osadminv1.CompleteCredentialsRequest{EnrolmentId: "x", TotpCode: "000000"}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_DONE")
	if n := len(b.store.Read().Admins); n != 0 {
		t.Fatalf("%d admins", n)
	}
}

// Invitations and Recover access use the same code pages after setup, by
// design.
func TestInvitationsAndRecoverAccessWorkAfterSetup(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	if _, err := setupClient(alice).AddRecoveryKey(ctx, connect.NewRequest(&osadminv1.AddRecoveryKeyRequest{PublicKey: newKey(t).line})); err != nil {
		t.Fatal(err)
	}
	b.finishSetup()
	if err := b.store.Update(rosterOf("alice")); err != nil {
		t.Fatal(err)
	}
	out, err := alice.access().AddAdmin(ctx, connect.NewRequest(&osadminv1.AddAdminRequest{Name: "carol", Role: osadminv1.Role_ROLE_ADMIN}))
	if err != nil {
		t.Fatal(err)
	}
	b.browser().enrol(t, out.Msg.GetInvitation().GetCode(), "carol", "a long enough passphrase")
	code, _ := b.srv.BeginRecoverAccess()
	b.browser().enrol(t, code, "dave", "dave's long passphrase")
	st := b.store.Read()
	for _, n := range []string{"carol", "dave"} {
		if a, ok := st.Admin(n); !ok || !a.HasCredentials() {
			t.Fatalf("%s: %+v", n, a)
		}
	}
}

// The setup-only methods are the rules table's; the API reference names
// each one.
func TestEverySetupOnlyMethodIsDocumented(t *testing.T) {
	doc := mustRead(t, "../../docs/osadmin-api.md")
	i := strings.Index(doc, "Setup only:")
	if i < 0 {
		t.Fatal("docs/osadmin-api.md has no \"Setup only:\" paragraph")
	}
	para, _, _ := strings.Cut(doc[i:], "\n\n")
	para = strings.ReplaceAll(para, "\n", " ")
	n := 0
	protoregistry.GlobalFiles.RangeFilesByPackage("sneakers.appliance.osadmin.v1", func(fd protoreflect.FileDescriptor) bool {
		for i := range fd.Services().Len() {
			s := fd.Services().Get(i)
			for j := range s.Methods().Len() {
				m := s.Methods().Get(j)
				if !osadmin.RuleOf(m).GetSetupOnly() {
					continue
				}
				n++
				if !strings.Contains(para, "`"+string(s.Name())+"."+string(m.Name())+"`") {
					t.Errorf("the Setup only paragraph doesn't name %s.%s", s.Name(), m.Name())
				}
			}
		}
		return true
	})
	if n != 3 {
		t.Fatalf("%d setup-only methods: AcknowledgeStep, AcknowledgeSingleAdmin and Finish are", n)
	}
}
