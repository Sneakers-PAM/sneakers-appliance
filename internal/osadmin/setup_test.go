// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

// acknowledge marks the network and protection steps seen.
func acknowledge(t *testing.T, su osadminv1connect.SetupServiceClient) {
	t.Helper()
	for _, s := range []osadminv1.SetupStepKind{osadminv1.SetupStepKind_SETUP_STEP_KIND_NETWORK, osadminv1.SetupStepKind_SETUP_STEP_KIND_PROTECTION} {
		if _, err := su.AcknowledgeStep(context.Background(), connect.NewRequest(&osadminv1.AcknowledgeStepRequest{Step: s})); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSetupFlow(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	su := osadminv1connect.NewSetupServiceClient(alice.hc, b.ts.URL)

	g, err := su.GetSetup(ctx, connect.NewRequest(&osadminv1.GetSetupRequest{}))
	if err != nil || g.Msg.GetDone() || !g.Msg.GetSingleAdminWarning() || g.Msg.GetMaxRecoveryKeys() != 3 {
		t.Fatalf("%v %v", g, err)
	}
	if g.Msg.GetProductSetupUrl() != "https://box1.sneakers.example.org/setup" {
		t.Fatal(g.Msg.GetProductSetupUrl())
	}
	_, err = su.Finish(ctx, connect.NewRequest(&osadminv1.FinishRequest{}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_INCOMPLETE")
	_, err = su.DownloadEscrow(ctx, connect.NewRequest(&osadminv1.DownloadEscrowRequest{}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_INCOMPLETE")

	_, err = su.AddRecoveryKey(ctx, connect.NewRequest(&osadminv1.AddRecoveryKeyRequest{PublicKey: b.keys["alice"].line}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ACCESS_KEY_DUPLICATE")

	var rks []sshKey
	for i := range 3 {
		k := newKey(t)
		rks = append(rks, k)
		if _, err := su.AddRecoveryKey(ctx, connect.NewRequest(&osadminv1.AddRecoveryKeyRequest{PublicKey: k.line, Label: "safe"})); err != nil {
			t.Fatal(err)
		}
		if len(b.init.escrowFor) != i+1 {
			t.Fatalf("the escrow goes to every recovery key: %d", len(b.init.escrowFor))
		}
		b.clk.Advance(1e9)
	}
	_, err = su.AddRecoveryKey(ctx, connect.NewRequest(&osadminv1.AddRecoveryKeyRequest{PublicKey: newKey(t).line}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ACCESS_RECOVERY_KEY_LIMIT")

	esc, err := su.DownloadEscrow(ctx, connect.NewRequest(&osadminv1.DownloadEscrowRequest{}))
	if err != nil || len(esc.Msg.GetContent()) == 0 {
		t.Fatalf("%v %v", esc, err)
	}
	if e := lastEntry(t, b.log, "setup.escrow.download"); e.Outcome != "ok" {
		t.Fatal("download audited")
	}
	acknowledge(t, su)

	_, err = su.Finish(ctx, connect.NewRequest(&osadminv1.FinishRequest{}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "single-admin")
	if _, err := su.AcknowledgeSingleAdmin(ctx, connect.NewRequest(&osadminv1.AcknowledgeSingleAdminRequest{})); err != nil {
		t.Fatal(err)
	}
	fin, err := su.Finish(ctx, connect.NewRequest(&osadminv1.FinishRequest{}))
	if err != nil || fin.Msg.GetProductSetupUrl() == "" {
		t.Fatalf("%v %v", fin, err)
	}
	if _, err := os.Stat(filepath.Join(b.state, "setup", osadmin.DoneMarker)); err != nil {
		t.Fatal("done marker")
	}
	b.done = b.srv.SetupDone()

	for _, k := range rks[:2] {
		if _, err := su.RemoveRecoveryKey(ctx, connect.NewRequest(&osadminv1.RemoveRecoveryKeyRequest{Fingerprint: k.fp})); err != nil {
			t.Fatal(err)
		}
	}
	_, err = su.RemoveRecoveryKey(ctx, connect.NewRequest(&osadminv1.RemoveRecoveryKeyRequest{Fingerprint: rks[2].fp}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ACCESS_LAST_RECOVERY_KEY")
}

func TestAFailedEscrowChangesNothing(t *testing.T) {
	b := newBox(t, false)
	b.init.escrowErr = connect.NewError(connect.CodeUnavailable, errors.New("init is busy"))
	alice := b.browser()
	alice.signIn("alice")
	su := osadminv1connect.NewSetupServiceClient(alice.hc, b.ts.URL)
	if _, err := su.AddRecoveryKey(context.Background(), connect.NewRequest(&osadminv1.AddRecoveryKeyRequest{PublicKey: newKey(t).line})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("got %v", err)
	}
	if n := len(b.store.Read().RecoveryKeys); n != 0 {
		t.Fatalf("%d recovery keys", n)
	}
}

func TestTwoAdminsNeedNoSingleAdminWarning(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	su := osadminv1connect.NewSetupServiceClient(alice.hc, b.ts.URL)
	if _, err := su.AddRecoveryKey(ctx, connect.NewRequest(&osadminv1.AddRecoveryKeyRequest{PublicKey: newKey(t).line})); err != nil {
		t.Fatal(err)
	}
	acknowledge(t, su)
	if _, err := su.Finish(ctx, connect.NewRequest(&osadminv1.FinishRequest{})); err != nil {
		t.Fatal(err)
	}
}

func TestAnAdminCantFinishSetup(t *testing.T) {
	b := newBox(t, true)
	bob := b.browser()
	bob.signIn("bob")
	_, err := osadminv1connect.NewSetupServiceClient(bob.hc, b.ts.URL).Finish(context.Background(), connect.NewRequest(&osadminv1.FinishRequest{}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}

// Setup can't finish before the first :8443 sign-in: the console's
// Complete (as root) checks it like every other step.
func TestFinishNeedsAFirstSignIn(t *testing.T) {
	b := newBox(t, false)
	h := b.srv.Handlers()
	local := func(procedure string, fn func(context.Context) error) error {
		return b.srv.RunLocal(context.Background(), osadmin.Local{}, procedure, fn)
	}
	if err := local(osadminv1connect.SetupServiceAddRecoveryKeyProcedure, func(ctx context.Context) error {
		_, err := h.Setup.AddRecoveryKey(ctx, connect.NewRequest(&osadminv1.AddRecoveryKeyRequest{PublicKey: newKey(t).line, Label: "safe"}))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := local(osadminv1connect.SetupServiceAcknowledgeSingleAdminProcedure, func(ctx context.Context) error {
		_, err := h.Setup.AcknowledgeSingleAdmin(ctx, connect.NewRequest(&osadminv1.AcknowledgeSingleAdminRequest{}))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []osadminv1.SetupStepKind{osadminv1.SetupStepKind_SETUP_STEP_KIND_NETWORK, osadminv1.SetupStepKind_SETUP_STEP_KIND_PROTECTION} {
		if err := local(osadminv1connect.SetupServiceAcknowledgeStepProcedure, func(ctx context.Context) error {
			_, err := h.Setup.AcknowledgeStep(ctx, connect.NewRequest(&osadminv1.AcknowledgeStepRequest{Step: s}))
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	finish := func() error {
		return local(osadminv1connect.SetupServiceFinishProcedure, func(ctx context.Context) error {
			_, err := h.Setup.Finish(ctx, connect.NewRequest(&osadminv1.FinishRequest{}))
			return err
		})
	}
	signedIn := func() bool {
		var got bool
		if err := local(osadminv1connect.SetupServiceGetSetupProcedure, func(ctx context.Context) error {
			r, err := h.Setup.GetSetup(ctx, connect.NewRequest(&osadminv1.GetSetupRequest{}))
			got = err == nil && r.Msg.GetSignedIn()
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return got
	}
	err := finish()
	symbolIn(t, err, connect.CodeFailedPrecondition, "SETUP_INCOMPLETE")
	if !strings.Contains(err.Error(), "sign in once") || signedIn() {
		t.Fatalf("%v", err)
	}
	b.browser().signIn("alice")
	if !signedIn() {
		t.Fatal("the first sign-in isn't recorded")
	}
	if err := finish(); err != nil {
		t.Fatal(err)
	}
}

func TestTheProductSetupURLFallsBackToTheBareManagementAddress(t *testing.T) {
	for mgmt, want := range map[string]string{
		"192.0.2.10/24":   "https://192.0.2.10/setup",
		"2001:db8::10/64": "https://[2001:db8::10]/setup",
	} {
		b := newBox(t, false)
		b.netd.hostname, b.netd.mgmt = "", []string{"fe80::10/64", mgmt}
		alice := b.browser()
		alice.signIn("alice")
		g, err := osadminv1connect.NewSetupServiceClient(alice.hc, b.ts.URL).GetSetup(context.Background(), connect.NewRequest(&osadminv1.GetSetupRequest{}))
		if err != nil || g.Msg.GetProductSetupUrl() != want {
			t.Fatalf("%s: %q %v", mgmt, g.Msg.GetProductSetupUrl(), err)
		}
	}
}
