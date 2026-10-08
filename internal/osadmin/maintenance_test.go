// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
)

// elevated gives bob a root shell: a challenge, its code, the ticket used
// up, so it's active.
func (b *box) elevated() elevation.Request {
	b.t.Helper()
	st := b.store.Read()
	c := elevation.Caller{Admin: "bob", KeyFP: b.keys["bob"].fp, Source: "192.0.2.50"}
	r, err := b.elev.Challenge(st, c, "investigate kubelet")
	if err != nil {
		b.t.Fatal(err)
	}
	_, code, err := b.elev.IssueCode(st, "bob", r.Challenge)
	if err != nil {
		b.t.Fatal(err)
	}
	_, ticket, err := b.elev.Open(st, c, r.Challenge, code)
	if err != nil {
		b.t.Fatal(err)
	}
	a, _, err := b.elev.Begin(ticket, "bob", 4242)
	if err != nil {
		b.t.Fatal(err)
	}
	return a
}

func (b *box) staged(alice *browser) {
	b.t.Helper()
	id, _ := alice.upload(b.t, bin(b.t, b.sign, b.enc, full(release.ChannelProduction)))
	if err := stage(alice, id); err != nil {
		b.t.Fatal(err)
	}
}

// requestElevation asks for a root-shell challenge as bob's closed shell
// would.
func (b *box) requestElevation() error {
	_, err := b.elev.Challenge(b.store.Read(), elevation.Caller{Admin: "bob", KeyFP: b.keys["bob"].fp, Source: "192.0.2.50"}, "check the disk")
	return err
}

// The apply sets maintenance before it activates the release, so nobody
// starts an elevated shell while the box goes down.
func TestApplyingBlocksNewElevation(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	b.staged(alice)
	var during error
	inMaintenance := false
	b.init.duringActivate = func() {
		inMaintenance = b.srv.Maintenance()
		during = b.requestElevation()
	}
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	if !inMaintenance {
		t.Fatal("the apply ran outside maintenance")
	}
	if c, ok := codes.Of(during); !ok || c != codes.ElevMaintenance {
		t.Fatalf("an elevation request during the apply: %v", during)
	}
	if !b.srv.Maintenance() {
		t.Fatal("maintenance ended while the box reboots into the release")
	}
	b.clk.Advance(osadmin.MaintenanceBound + time.Minute)
	if b.srv.Maintenance() {
		t.Fatal("a reboot that never came holds maintenance for ever")
	}
}

func TestAFailedApplyEndsMaintenance(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	b.staged(alice)
	b.init.activateErr = connect.NewError(connect.CodeInternal, errors.New("the ESP is read-only"))
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{TotpCode: b.code("alice")})); err == nil {
		t.Fatal("no error")
	}
	if b.srv.Maintenance() {
		t.Fatal("maintenance outlived the failed apply")
	}
	if err := b.requestElevation(); err != nil {
		t.Fatalf("elevation is still blocked: %v", err)
	}
}

func TestRevertingBlocksNewElevation(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	var during error
	b.init.duringActivate = func() { during = b.requestElevation() }
	if _, err := alice.upgrade().RevertUpdate(context.Background(), connect.NewRequest(&osadminv1.RevertUpdateRequest{TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	if c, ok := codes.Of(during); !ok || c != codes.ElevMaintenance {
		t.Fatalf("an elevation request during the revert: %v", during)
	}
}

// An active elevated shell holds the apply back: the owner is told which
// one, and ends it (or waits for it) first.
func TestAnActiveElevatedShellHoldsTheApply(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	b.staged(alice)
	r := b.elevated()
	ctx := context.Background()
	_, err := alice.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{TotpCode: b.code("alice")}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_ELEVATED")
	if !strings.Contains(err.Error(), r.ID) || !strings.Contains(err.Error(), "bob") {
		t.Fatalf("the refusal doesn't name the session: %v", err)
	}
	_, err = alice.upgrade().RevertUpdate(ctx, connect.NewRequest(&osadminv1.RevertUpdateRequest{TotpCode: b.code("alice")}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_ELEVATED")
	if b.init.activated != 0 || b.init.rollbacks != 0 || b.init.reboots != 0 {
		t.Fatal("the box went down under an elevated shell")
	}
	if b.srv.Maintenance() {
		t.Fatal("a refused apply left maintenance on")
	}
	if e := lastEntry(t, b.log, "upgrade.apply"); e.Outcome != "refused" || e.Code != "UPGRADE_ELEVATED" {
		t.Fatalf("%+v", e)
	}
	if err := b.elev.End(r.ID, elevation.ReasonExit, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{TotpCode: b.code("alice")})); err != nil {
		t.Fatalf("once the shell ended: %v", err)
	}
}

// The update window doesn't apply while an elevated shell is active; the
// next tick after it ends does.
func TestTheWindowWaitsForAnElevatedShell(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	open := b.clk.Now().Local().Add(-10 * time.Minute).Format("15:04")
	pol := &osadminv1.UpgradePolicy{Mode: "automatic", WindowStart: open, WindowMinutes: 60}
	if _, err := alice.upgrade().SetUpgradePolicy(ctx, connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol})); err != nil {
		t.Fatal(err)
	}
	b.staged(alice)
	r := b.elevated()
	b.srv.UpgradeWindowTick(ctx)
	if b.init.activated != 0 {
		t.Fatal("the window applied under an elevated shell")
	}
	if err := b.elev.End(r.ID, elevation.ReasonExit, ""); err != nil {
		t.Fatal(err)
	}
	b.srv.UpgradeWindowTick(ctx)
	if b.init.activated != 1 {
		t.Fatalf("applied %d times", b.init.activated)
	}
}

// endsOnSignal makes a signalled session end itself, as its
// sneakers-elevated does on SIGTERM.
func (b *box) endsOnSignal() {
	b.onSignal = func(pid int) {
		for _, r := range b.elev.List() {
			if r.State == elevation.Active && r.PID == pid {
				_ = b.elev.End(r.ID, elevation.ReasonTerminated, "")
			}
		}
	}
}

func override(r elevation.Request, confirm string) *osadminv1.ElevationOverride {
	return &osadminv1.ElevationOverride{ElevationId: r.ID, Confirm: confirm, Reason: "the security fix can't wait"}
}

// The owner's override ends the elevated shell, audited with the reason,
// and only then applies.
func TestAnOwnerOverrideEndsTheShellThenApplies(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	b.staged(alice)
	b.endsOnSignal()
	r := b.elevated()
	var stateAtActivate elevation.State
	b.init.duringActivate = func() {
		got, _ := b.elev.Get(r.ID)
		stateAtActivate = got.State
	}
	req := &osadminv1.ApplyUpdateRequest{ElevationOverride: override(r, "bob "+r.ID), TotpCode: b.code("alice")}
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(req)); err != nil {
		t.Fatal(err)
	}
	if stateAtActivate != elevation.Ended {
		t.Fatalf("the release activated with the session %q", stateAtActivate)
	}
	if b.init.activated != 1 || b.init.reboots != 1 {
		t.Fatalf("activated %d, rebooted %d", b.init.activated, b.init.reboots)
	}
	e := lastEntry(t, b.log, "elevation.terminate")
	if e.Outcome != "ok" || e.Target != r.Name() || e.Detail["request"] != r.ID || e.Actor != "alice" || e.Detail["reason"] != "the security fix can't wait" || e.Detail["admin"] != "bob" || e.Detail["for"] != "upgrade.apply" {
		t.Fatalf("%+v", e)
	}
	if e := lastEntry(t, b.log, "upgrade.apply"); e.Outcome != "ok" || e.Detail["overrode"] != r.ID {
		t.Fatalf("%+v", e)
	}
}

func TestAnOwnerOverrideEndsTheShellThenReverts(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	b.endsOnSignal()
	r := b.elevated()
	req := &osadminv1.RevertUpdateRequest{ElevationOverride: override(r, "bob "+r.ID), TotpCode: b.code("alice")}
	if _, err := alice.upgrade().RevertUpdate(context.Background(), connect.NewRequest(req)); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.elev.Get(r.ID); got.State != elevation.Ended {
		t.Fatalf("the session is %s", got.State)
	}
	if b.init.rollbacks != 1 {
		t.Fatalf("rolled back %d times", b.init.rollbacks)
	}
}

// A wrong confirmation, a missing reason or an override naming another
// request is refused, and the shell stays open.
func TestAWrongOverrideIsRefused(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	b.staged(alice)
	b.endsOnSignal()
	r := b.elevated()
	ctx := context.Background()
	noReason := override(r, "bob "+r.ID)
	noReason.Reason = " "
	other := override(r, "bob E-ZZZZ")
	other.ElevationId = "E-ZZZZ"
	for name, o := range map[string]*osadminv1.ElevationOverride{
		"wrong admin":    override(r, "alice "+r.ID),
		"wrong request":  override(r, "bob E-ZZZZ"),
		"empty":          override(r, ""),
		"no reason":      noReason,
		"another id":     other,
		"case or spaces": override(r, " BOB  "+strings.ToLower(r.ID)),
	} {
		_, err := alice.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{ElevationOverride: o, TotpCode: b.code("alice")}))
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		if name == "another id" {
			symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_ELEVATED")
		} else {
			symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_CONFIRM")
		}
	}
	if got, _ := b.elev.Get(r.ID); got.State != elevation.Active || len(b.signals) != 0 {
		t.Fatalf("a refused override touched the session: %s, %v", got.State, b.signals)
	}
	if b.init.activated != 0 || b.srv.Maintenance() {
		t.Fatal("a refused override applied or left maintenance on")
	}
}

// Only an owner may override: an admin's apply, override or not, is
// refused before anything is ended.
func TestANonOwnerCantOverride(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	b.staged(alice)
	b.endsOnSignal()
	r := b.elevated()
	bob := b.browser()
	bob.signIn("bob")
	_, err := bob.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{ElevationOverride: override(r, "bob "+r.ID), TotpCode: b.code("bob")}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("want permission denied, got %v", err)
	}
	if got, _ := b.elev.Get(r.ID); got.State != elevation.Active || len(b.signals) != 0 || b.init.activated != 0 {
		t.Fatal("an admin's override ended the session or applied")
	}
}

// A session that doesn't end in time holds the apply back: nothing
// activates under it.
func TestAnOverrideWaitsForTheSessionToEnd(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	b.staged(alice)
	r := b.elevated()
	_, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{ElevationOverride: override(r, "bob "+r.ID), TotpCode: b.code("alice")}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_ELEVATED")
	if len(b.signals) != 1 || b.init.activated != 0 || b.srv.Maintenance() {
		t.Fatalf("signals %v, activated %d", b.signals, b.init.activated)
	}
}

// Updates names the open elevated shells, so the page can show who holds
// one before the owner tries.
func TestUpdatesNamesTheOpenElevatedShell(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	r := b.elevated()
	got, err := alice.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	es := got.Msg.GetActiveElevations()
	if len(es) != 1 || es[0].GetId() != r.ID || es[0].GetAdmin() != "bob" {
		t.Fatalf("%v", es)
	}
}
