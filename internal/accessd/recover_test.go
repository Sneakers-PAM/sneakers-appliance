// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
)

// The console's Recover access, over the socket: a recovery window, a key
// typed on the console, the typed yes, and the 24-hour hold.
func TestRecoverAccessOverTheSocket(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	chc, curl := b.console()
	console := accessv1connect.NewEnrolmentServiceClient(chc, curl)
	open, err := console.OpenEnrolment(ctx, connect.NewRequest(&accessv1.OpenEnrolmentRequest{Admin: "alice", Recovery: true}))
	if err != nil || !open.Msg.GetEnrolment().GetRecovery() {
		t.Fatalf("%v %v", open, err)
	}
	k := newKey(t)
	off, err := console.OfferEnrolmentKey(ctx, connect.NewRequest(&accessv1.OfferEnrolmentKeyRequest{PublicKey: k.line, Via: access.ViaTyped}))
	if err != nil || off.Msg.GetKey().GetState() != "waiting" || off.Msg.GetKey().GetVia() != access.ViaTyped || off.Msg.GetKey().GetFingerprint() != k.fp {
		t.Fatalf("%v %v", off, err)
	}
	if _, err := console.AcceptEnrolmentKey(ctx, connect.NewRequest(&accessv1.AcceptEnrolmentKeyRequest{Id: off.Msg.GetKey().GetId(), Confirm: "yes"})); err != nil {
		t.Fatal(err)
	}
	st := b.store.Read()
	a, _ := st.Admin("alice")
	if a.ApprovalHoldUntil == nil || a.Keys[len(a.Keys)-1].Via != access.ViaConsoleRecovery {
		t.Fatalf("%+v", a)
	}
	if e := lastEntry(t, b.log, "access.console-recovery"); e.KeyFP != k.fp || e.Outcome != "ok" {
		t.Fatalf("%+v", e)
	}

	// Recover access is for owners, and offering is the console's.
	_, err = console.OpenEnrolment(ctx, connect.NewRequest(&accessv1.OpenEnrolmentRequest{Admin: "bob", Recovery: true}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ACCESS_FORBIDDEN")
	ahc, aurl := b.as(b.uids["alice"])
	_, err = accessv1connect.NewEnrolmentServiceClient(ahc, aurl).OfferEnrolmentKey(ctx, connect.NewRequest(&accessv1.OfferEnrolmentKeyRequest{PublicKey: newKey(t).line, Via: access.ViaTyped}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}

// The console confirms the single-admin warning (root only); the setup
// state reports it, and an owner's shell can't.
func TestTheConsoleAcknowledgesTheSingleAdminWarning(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	chc, curl := b.console()
	setup := accessv1connect.NewSetupServiceClient(chc, curl)
	if _, err := setup.AcknowledgeSingleAdmin(ctx, connect.NewRequest(&accessv1.AcknowledgeSingleAdminRequest{})); err != nil {
		t.Fatal(err)
	}
	g, err := setup.GetSetup(ctx, connect.NewRequest(&accessv1.GetSetupRequest{}))
	if err != nil || !g.Msg.GetSetup().GetSingleAdminAcknowledged() {
		t.Fatalf("%v %v", g, err)
	}
	ahc, aurl := b.as(b.uids["alice"])
	_, err = accessv1connect.NewSetupServiceClient(ahc, aurl, connect.WithInterceptors(keyHeader(b.keys["alice"].fp))).AcknowledgeSingleAdmin(ctx, connect.NewRequest(&accessv1.AcknowledgeSingleAdminRequest{}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}
