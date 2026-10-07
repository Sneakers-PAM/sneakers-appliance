// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

const host = "box1.sneakers.example.org"

func (br *browser) power() osadminv1connect.PowerServiceClient {
	return osadminv1connect.NewPowerServiceClient(br.hc, br.b.ts.URL)
}

func start(t *testing.T, br *browser) *osadminv1.FactoryReset {
	t.Helper()
	r, err := br.power().StartFactoryReset(context.Background(), connect.NewRequest(&osadminv1.StartFactoryResetRequest{ConfirmHostname: host}))
	if err != nil {
		t.Fatal(err)
	}
	return r.Msg.GetFactoryReset()
}

func approve(br *browser, id string) error {
	_, err := br.power().ApproveFactoryReset(context.Background(), connect.NewRequest(&osadminv1.ApproveFactoryResetRequest{Id: id}))
	return err
}

func TestFactoryResetByQuorum(t *testing.T) {
	b := newBox(t, true)
	alice, bob := b.browser(), b.browser()
	alice.signIn("alice")
	bob.signIn("bob")
	ctx := context.Background()

	_, err := alice.power().StartFactoryReset(ctx, connect.NewRequest(&osadminv1.StartFactoryResetRequest{ConfirmHostname: "box1"}))
	symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_CONFIRM")
	_, err = bob.power().StartFactoryReset(ctx, connect.NewRequest(&osadminv1.StartFactoryResetRequest{ConfirmHostname: host}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")

	fr := start(t, alice)
	if fr.GetState() != osadminv1.FactoryResetState_FACTORY_RESET_STATE_PENDING || fr.GetRequired() != 2 || len(fr.GetApprovals()) != 1 {
		t.Fatalf("the starter's approval counts once: %v", fr)
	}
	symbolIn(t, approve(alice, fr.GetId()), connect.CodeFailedPrecondition, "RESET_APPROVED")
	if e := lastEntry(t, b.log, "power.factory-reset.approve"); e.Outcome != "refused" || e.Code != "RESET_APPROVED" {
		t.Fatalf("a second self-approval is audited and refused: %+v", e)
	}
	b.clk.Advance(osadmin.ResetPendingLifetime - time.Minute)
	bob.signIn("bob")
	if err := approve(bob, fr.GetId()); err != nil {
		t.Fatal(err)
	}
	got := b.srv.FactoryReset()
	if got.GetState() != osadminv1.FactoryResetState_FACTORY_RESET_STATE_COUNTDOWN || !got.GetRunsAt().AsTime().Equal(b.clk.Now().Add(osadmin.ResetDelay)) {
		t.Fatalf("the quorum starts the 10-minute delay: %v", got)
	}
	st, err := osadminv1connect.NewStatusServiceClient(bob.hc, b.ts.URL).GetStatus(ctx, connect.NewRequest(&osadminv1.GetStatusRequest{}))
	if err != nil || st.Msg.GetFactoryReset().GetId() != fr.GetId() || !kinds(st.Msg.GetWarnings())[osadminv1.WarningKind_WARNING_KIND_FACTORY_RESET] {
		t.Fatalf("Status shows the countdown: %v %v", st, err)
	}
	b.clk.Advance(osadmin.ResetDelay - time.Second)
	if len(b.init.resets) != 0 {
		t.Fatal("not before the delay ends")
	}
	b.clk.Advance(time.Second)
	if len(b.init.resets) != 1 || b.init.resets[0].GetStartedBy() != "alice" || len(b.init.resets[0].GetApprovals()) != 2 {
		t.Fatalf("init runs the reset: %v", b.init.resets)
	}
	if e := lastEntry(t, b.log, "power.factory-reset.run"); e.Outcome != "ok" || e.Detail["approvals"] != "alice,bob" {
		t.Fatalf("%+v", e)
	}
}

func TestNoResetWithoutTheQuorum(t *testing.T) {
	b := newBox(t, true)
	b.addAdmin("carol", access.RoleOwner)
	alice, carol := b.browser(), b.browser()
	alice.signIn("alice")
	carol.signIn("carol")
	if _, err := alice.access().SetQuorum(context.Background(), connect.NewRequest(&osadminv1.SetQuorumRequest{Members: []string{"alice", "bob", "carol"}, Required: 3})); err != nil {
		t.Fatal(err)
	}
	fr := start(t, alice)
	if err := approve(carol, fr.GetId()); err != nil {
		t.Fatal(err)
	}
	if b.srv.FactoryReset().GetState() != osadminv1.FactoryResetState_FACTORY_RESET_STATE_PENDING {
		t.Fatal("two of three isn't the quorum")
	}
	b.clk.Advance(osadmin.ResetPendingLifetime + osadmin.ResetDelay)
	if len(b.init.resets) != 0 || b.srv.FactoryReset() != nil {
		t.Fatal("an unapproved request expires and never runs")
	}
	if e := lastEntry(t, b.log, "power.factory-reset.expire"); e.Code != "RESET_CANCELLED" {
		t.Fatalf("%+v", e)
	}
	carol.signIn("carol")
	symbolIn(t, approve(carol, fr.GetId()), connect.CodeFailedPrecondition, "RESET_CANCELLED")
}

func TestAnyAdminCancelsTheCountdown(t *testing.T) {
	b := newBox(t, true)
	b.addAdmin("carol", access.RoleOwner)
	alice, carol, bob := b.browser(), b.browser(), b.browser()
	alice.signIn("alice")
	carol.signIn("carol")
	bob.signIn("bob")
	if _, err := alice.access().SetQuorum(context.Background(), connect.NewRequest(&osadminv1.SetQuorumRequest{Members: []string{"alice", "carol"}, Required: 2})); err != nil {
		t.Fatal(err)
	}
	fr := start(t, alice)
	symbolIn(t, approve(bob, fr.GetId()), connect.CodeFailedPrecondition, "RESET_APPROVED")
	if err := approve(carol, fr.GetId()); err != nil {
		t.Fatal(err)
	}
	b.clk.Advance(osadmin.ResetDelay / 2)
	if _, err := bob.power().CancelFactoryReset(context.Background(), connect.NewRequest(&osadminv1.CancelFactoryResetRequest{Id: fr.GetId()})); err != nil {
		t.Fatalf("an admin off the roster may cancel: %v", err)
	}
	b.clk.Advance(osadmin.ResetDelay)
	if len(b.init.resets) != 0 {
		t.Fatal("a cancelled reset never runs")
	}
	if e := lastEntry(t, b.log, "power.factory-reset.cancel"); e.Actor != "bob" || e.Outcome != "ok" {
		t.Fatalf("%+v", e)
	}
	carol.signIn("carol")
	symbolIn(t, approve(carol, fr.GetId()), connect.CodeFailedPrecondition, "RESET_CANCELLED")
}

func TestTheConsoleCancels(t *testing.T) {
	b := newBox(t, true)
	alice, bob := b.browser(), b.browser()
	alice.signIn("alice")
	bob.signIn("bob")
	fr := start(t, alice)
	if err := approve(bob, fr.GetId()); err != nil {
		t.Fatal(err)
	}
	if err := b.srv.CancelFactoryResetLocal(0, ""); err != nil {
		t.Fatal(err)
	}
	b.clk.Advance(osadmin.ResetDelay)
	if len(b.init.resets) != 0 {
		t.Fatal("cancelled from the console")
	}
	if e := lastEntry(t, b.log, "power.factory-reset.cancel"); e.Actor != "console" || e.Detail["surface"] != "console" {
		t.Fatalf("%+v", e)
	}
}

func TestNoResetWithASingleAdmin(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	gp, err := alice.power().GetPower(ctx, connect.NewRequest(&osadminv1.GetPowerRequest{}))
	if err != nil || gp.Msg.GetFactoryResetAvailable() || gp.Msg.GetFactoryResetUnavailableReason() == "" {
		t.Fatalf("not offered: %v %v", gp, err)
	}
	_, err = alice.power().StartFactoryReset(ctx, connect.NewRequest(&osadminv1.StartFactoryResetRequest{ConfirmHostname: host}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "RESET_UNAVAILABLE")
}

func TestQuorumRoster(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	l, err := alice.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	if err != nil || l.Msg.GetQuorum().GetRequired() != 2 || l.Msg.GetQuorum().GetConfigured() || len(l.Msg.GetQuorum().GetMembers()) != 2 {
		t.Fatalf("the default roster: %v %v", l, err)
	}
	_, err = alice.access().SetQuorum(ctx, connect.NewRequest(&osadminv1.SetQuorumRequest{Members: []string{"alice"}, Required: 1}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "RESET_UNAVAILABLE")
	_, err = alice.access().SetQuorum(ctx, connect.NewRequest(&osadminv1.SetQuorumRequest{Members: []string{"alice", "zed"}, Required: 2}))
	symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_NAME")
	bob := b.browser()
	bob.signIn("bob")
	_, err = bob.access().SetQuorum(ctx, connect.NewRequest(&osadminv1.SetQuorumRequest{Members: []string{"alice", "bob"}, Required: 2}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}

func TestForcedPowerNeedsTheSecondConfirmation(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	_, err := alice.power().Reboot(ctx, connect.NewRequest(&osadminv1.RebootRequest{Forced: true}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "POWER_FORCED_CONFIRM")
	_, err = alice.power().Shutdown(ctx, connect.NewRequest(&osadminv1.ShutdownRequest{Forced: true}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "POWER_FORCED_CONFIRM")
	if b.init.reboots+b.init.poweroffs != 0 {
		t.Fatal("nothing happens without the second confirmation")
	}
	if _, err := alice.power().Reboot(ctx, connect.NewRequest(&osadminv1.RebootRequest{Forced: true, ForcedConfirmed: true})); err != nil {
		t.Fatal(err)
	}
	if !b.init.forced || b.init.reboots != 1 {
		t.Fatal("init told to force")
	}
	if e := lastEntry(t, b.log, "power.reboot"); e.Detail["mode"] != "forced" || e.Outcome != "ok" {
		t.Fatalf("the forced flag is audited: %+v", e)
	}
	if _, err := alice.power().Shutdown(ctx, connect.NewRequest(&osadminv1.ShutdownRequest{})); err != nil {
		t.Fatal(err)
	}
	if b.init.forced {
		t.Fatal("graceful stays the default")
	}
}

func TestTheQuorumArmsInitAndACancelReachesIt(t *testing.T) {
	b := newBox(t, true)
	alice, bob := b.browser(), b.browser()
	alice.signIn("alice")
	bob.signIn("bob")
	fr := start(t, alice)
	if len(b.init.arms) != 0 {
		t.Fatal("init is armed before the quorum approves")
	}
	if err := approve(bob, fr.GetId()); err != nil {
		t.Fatal(err)
	}
	if len(b.init.arms) != 1 || b.init.arms[0].GetId() != fr.GetId() || b.init.arms[0].GetStartedBy() != "alice" || len(b.init.arms[0].GetApprovals()) != 2 {
		t.Fatalf("init is armed with the quorum: %v", b.init.arms)
	}
	if _, err := bob.power().CancelFactoryReset(context.Background(), connect.NewRequest(&osadminv1.CancelFactoryResetRequest{Id: fr.GetId()})); err != nil {
		t.Fatal(err)
	}
	if len(b.init.cancels) != 1 || b.init.cancels[0] != fr.GetId() {
		t.Fatalf("the cancel reaches init: %v", b.init.cancels)
	}
}

func TestTheRunNamesTheArmedRequest(t *testing.T) {
	b := newBox(t, true)
	alice, bob := b.browser(), b.browser()
	alice.signIn("alice")
	bob.signIn("bob")
	fr := start(t, alice)
	if err := approve(bob, fr.GetId()); err != nil {
		t.Fatal(err)
	}
	b.clk.Advance(osadmin.ResetDelay)
	if len(b.init.resets) != 1 || b.init.resets[0].GetId() != fr.GetId() {
		t.Fatalf("%v", b.init.resets)
	}
}

func TestNoCountdownWhenInitRefusesToArm(t *testing.T) {
	b := newBox(t, true)
	b.init.armErr = connect.NewError(connect.CodeFailedPrecondition, errors.New("RESET_QUORUM (3606): \"bob\" isn't on the quorum roster"))
	alice, bob := b.browser(), b.browser()
	alice.signIn("alice")
	bob.signIn("bob")
	fr := start(t, alice)
	symbolIn(t, approve(bob, fr.GetId()), connect.CodeFailedPrecondition, "RESET_QUORUM")
	got := b.srv.FactoryReset()
	if got.GetState() != osadminv1.FactoryResetState_FACTORY_RESET_STATE_PENDING || len(got.GetApprovals()) != 1 {
		t.Fatalf("a refused arm leaves the request as it was: %v", got)
	}
	b.clk.Advance(osadmin.ResetDelay)
	if len(b.init.resets) != 0 {
		t.Fatal("a reset init refused to arm ran")
	}
}
