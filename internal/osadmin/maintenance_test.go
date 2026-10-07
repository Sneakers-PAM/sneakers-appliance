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

// elevated gives bob an elevated shell: requested, approved by alice and
// connected, so it's active.
func (b *box) elevated() elevation.Request {
	b.t.Helper()
	st := b.store.Read()
	r, err := b.elev.Request(st, elevation.Caller{Admin: "bob", KeyFP: b.keys["bob"].fp, Source: "192.0.2.50"}, "investigate kubelet", 30)
	if err != nil {
		b.t.Fatal(err)
	}
	a, err := b.elev.Approve(st, "alice", r.ID, 0)
	if err != nil {
		b.t.Fatal(err)
	}
	if _, _, err := b.elev.Begin(a.Certificate, 4242); err != nil {
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

// requestElevation asks for an elevated shell as bob's closed shell would.
func (b *box) requestElevation() error {
	_, err := b.elev.Request(b.store.Read(), elevation.Caller{Admin: "bob", KeyFP: b.keys["bob"].fp, Source: "192.0.2.50"}, "check the disk", 30)
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
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{})); err != nil {
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
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{})); err == nil {
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
	if _, err := alice.upgrade().RevertUpdate(context.Background(), connect.NewRequest(&osadminv1.RevertUpdateRequest{})); err != nil {
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
	_, err := alice.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_ELEVATED")
	if !strings.Contains(err.Error(), r.ID) || !strings.Contains(err.Error(), "bob") {
		t.Fatalf("the refusal doesn't name the session: %v", err)
	}
	_, err = alice.upgrade().RevertUpdate(ctx, connect.NewRequest(&osadminv1.RevertUpdateRequest{}))
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
	if _, err := alice.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{})); err != nil {
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
