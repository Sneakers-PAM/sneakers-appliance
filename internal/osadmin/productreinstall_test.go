// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// A bundle of the installed version stages and applies like an update: k0s
// restarts from the fresh slot, the replaced slot is the way back, and the
// apply is a reinstall in the history and the audit log.
func TestTheInstalledVersionReinstalls(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	alice.installProduct(t, "0.2.0")
	before := len(b.services.log())
	alice.installProduct(t, "0.2.0")
	if got := b.services.log()[before:]; !slices.Equal(got, []string{"stop k0s", "start k0s"}) {
		t.Fatalf("services %v", got)
	}
	if s := alice.productSlots(t); s.GetInstalledVersion() != "0.2.0" || s.GetPreviousVersion() != "0.2.0" || s.GetStagedVersion() != "" {
		t.Fatalf("slots %v", s)
	}
	if h := alice.upgrades(t).GetHistory()[0]; h.GetAction() != "reinstall" || h.GetVersion() != "0.2.0" || h.GetOutcome() != "ok" {
		t.Fatalf("history %v", h)
	}
	if e := lastEntry(t, b.log, "product.reinstall"); e.Actor != "alice" || e.Outcome != "ok" || e.Detail["version"] != "0.2.0" {
		t.Fatalf("audit %+v", e)
	}
	if e := lastEntry(t, b.log, "upgrade.apply"); e.Outcome != "ok" {
		t.Fatalf("audit %+v", e)
	}
	if _, err := alice.upgrade().RevertUpdate(context.Background(), connect.NewRequest(&osadminv1.RevertUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
}

// Check updates offers the installed version to reinstall, apart from the
// newer versions; with no product there's nothing to reinstall.
func TestTheCheckOffersTheInstalledVersionToReinstall(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	v2, v3 := productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"), productBin(t, b.sign, b.enc, "0.3.0", "0.1.0")
	b.mirrorFiles[updatepkg.IndexName] = index(t, v2, v3)
	pol := &osadminv1.UpgradePolicy{Mode: "manual", WindowStart: "02:00", WindowMinutes: 120, MirrorUrl: b.mirror.URL}
	if _, err := alice.upgrade().SetUpgradePolicy(ctx, connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol})); err != nil {
		t.Fatal(err)
	}
	check := func() *osadminv1.CheckUpdatesResponse {
		t.Helper()
		c, err := alice.upgrade().CheckUpdates(ctx, connect.NewRequest(&osadminv1.CheckUpdatesRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return c.Msg
	}
	if c := check(); c.GetProductReinstall() != nil || len(c.GetProduct()) != 2 {
		t.Fatalf("with no product: %v", c)
	}
	alice.installProduct(t, "0.2.0")
	c := check()
	if r := c.GetProductReinstall(); r.GetVersion() != "0.2.0" || r.GetFileName() == "" || r.GetTarget() != product {
		t.Fatalf("reinstall offer %v", r)
	}
	if len(c.GetProduct()) != 1 || c.GetProduct()[0].GetVersion() != "0.3.0" {
		t.Fatalf("newer offers %v", c.GetProduct())
	}
	b.mirrorFiles[c.GetProductReinstall().GetFileName()] = v2
	f, err := alice.upgrade().FetchUpdate(ctx, connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: c.GetProductReinstall().GetFileName()}))
	if err != nil {
		t.Fatal(err)
	}
	if err := stage(alice, f.Msg.GetUploadId()); err != nil {
		t.Fatal(err)
	}
	if s := alice.productSlots(t); s.GetStagedVersion() != "0.2.0" || s.GetInstalledVersion() != "0.2.0" {
		t.Fatalf("slots %v", s)
	}
}

// The update window never reinstalls, and never installs the bundle a
// product reset kept: both wait for an owner.
func TestTheWindowLeavesAReinstallAndAResetsBundleToAnOwner(t *testing.T) {
	fake := &fakeReset{}
	b := newBox(t, false, func(b *box, o *osadmin.Options) { fake.b = b; o.ProductReset = fake })
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	open := b.clk.Now().Local().Add(-10 * time.Minute).Format("15:04")
	pol := &osadminv1.UpgradePolicy{Mode: "automatic", WindowStart: open, WindowMinutes: 60}
	if _, err := alice.upgrade().SetUpgradePolicy(ctx, connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol})); err != nil {
		t.Fatal(err)
	}
	alice.installProduct(t, "0.2.0")
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	before := len(b.services.log())
	b.srv.UpgradeWindowTick(ctx)
	if got := b.services.log()[before:]; len(got) != 0 {
		t.Fatalf("the window reinstalled: %v", got)
	}
	b.services.running = true
	if _, err := resetAs(b, b.ssh("alice"), &osadminv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "sneakers"}); err != nil {
		t.Fatal(err)
	}
	before = len(b.services.log())
	b.clk.Advance(24 * time.Hour)
	b.srv.UpgradeWindowTick(ctx)
	if got := b.services.log()[before:]; len(got) != 0 {
		t.Fatalf("the window installed the reset's bundle: %v", got)
	}
	alice.signIn("alice")
	if s := alice.productSlots(t); s.GetInstalledVersion() != "" || s.GetStagedVersion() == "" {
		t.Fatalf("slots %v", s)
	}
}
