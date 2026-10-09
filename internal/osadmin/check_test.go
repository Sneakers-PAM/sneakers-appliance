// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

func unitsIndex(t *testing.T) []byte {
	t.Helper()
	var idx updatepkg.Index
	osFull := updatepkg.Header{Name: updatepkg.Name, Unit: updatepkg.UnitBaseOS, Version: "0.1.1", Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelProduction}
	osPatch := patchHeader("0.1.1", "0.1.0")
	osPatch.Name = updatepkg.Name
	webFits := updatepkg.Header{Name: updatepkg.NameWeb, Unit: updatepkg.UnitBaseWeb, Version: "0.1.2", Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelProduction}
	webNext := webFits
	webNext.Version = "0.2.0"
	prod := updatepkg.Header{Name: updatepkg.NameProduct, Version: "0.4.0", Arch: "amd64", Kind: updatepkg.KindProduct, MinBase: "0.1.0", Channel: release.ChannelProduction}
	idx.Add(osFull, 33<<20)
	idx.Add(osPatch, 1<<20)
	idx.Add(webFits, 500<<10)
	idx.Add(webNext, 500<<10)
	idx.Add(prod, 1<<30)
	b, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func setPolicy(t *testing.T, br *browser, pol *osadminv1.UpgradePolicy) error {
	t.Helper()
	pol.Mode, pol.WindowStart, pol.WindowMinutes = "manual", "02:00", 120
	_, err := br.upgrade().SetUpgradePolicy(context.Background(), connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol}))
	return err
}

func checkNow(br *browser) (*osadminv1.CheckUpdatesResponse, error) {
	r, err := br.upgrade().CheckUpdates(context.Background(), connect.NewRequest(&osadminv1.CheckUpdatesRequest{}))
	if err != nil {
		return nil, err
	}
	return r.Msg, nil
}

// Check now reads the index again on every press and answers what it
// offers for each unit, labelled full or patch, the patch preferred when
// it fits; GetUpgrades keeps the last answer.
func TestCheckNowOffersEachUnit(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	_, err := checkNow(alice)
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_AIR_GAPPED")
	b.mirrorFiles[updatepkg.IndexName] = unitsIndex(t)
	if err := setPolicy(t, alice, &osadminv1.UpgradePolicy{Source: osadmin.SourceManual, MirrorUrl: b.mirror.URL}); err != nil {
		t.Fatal(err)
	}
	c, err := checkNow(alice)
	if err != nil {
		t.Fatal(err)
	}
	if c.GetIndexFormat() != 2 || c.GetSource() != "mirror" || c.GetUrl() != b.mirror.URL || c.GetCheckedAt() == nil {
		t.Fatalf("check %v", c)
	}
	osOffers := c.GetBaseOs()
	if len(osOffers) != 2 || osOffers[0].GetKind() != "patch" || !osOffers[0].GetPreferred() || osOffers[1].GetKind() != "full" || osOffers[1].GetPreferred() || osOffers[1].GetSize() != 33<<20 {
		t.Fatalf("Base OS offers %v", osOffers)
	}
	if w := c.GetBaseWeb(); len(w) != 1 || w[0].GetVersion() != "0.1.2" || w[0].GetNeeds() != "0.1.0 to before 0.2.0" || !w[0].GetPreferred() {
		t.Fatalf("Base Web offers %v", w)
	}
	if !strings.HasPrefix(c.GetBaseWebWaits(), "Base Web 0.2.0 needs Base OS 0.2.0 to before 0.3.0") {
		t.Fatalf("the waiting Base Web: %q", c.GetBaseWebWaits())
	}
	if p := c.GetProduct(); len(p) != 1 || p[0].GetVersion() != "0.4.0" || p[0].GetNeeds() != "0.1.0 or newer" {
		t.Fatalf("product offers %v", p)
	}
	hits := b.mirrorHit
	if _, err := checkNow(alice); err != nil || b.mirrorHit != hits+1 {
		t.Fatalf("Check now didn't read the index again: %v", err)
	}
	g, _ := alice.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if len(g.Msg.GetLastCheck().GetBaseOs()) != 2 || g.Msg.GetMirrorStatus().GetSource() != osadmin.SourceManual || !g.Msg.GetMirrorStatus().GetChecked() {
		t.Fatalf("GetUpgrades %v %v", g.Msg.GetLastCheck(), g.Msg.GetMirrorStatus())
	}
}

// A box short of memory prefers the full file to a patch.
func TestASmallBoxPrefersTheFullFile(t *testing.T) {
	b := newBox(t, false, func(_ *box, o *osadmin.Options) { o.Upgrade.MemAvailable = func() int64 { return 300 << 20 } })
	alice := b.browser()
	alice.signIn("alice")
	b.mirrorFiles[updatepkg.IndexName] = unitsIndex(t)
	if err := setPolicy(t, alice, &osadminv1.UpgradePolicy{MirrorUrl: b.mirror.URL}); err != nil {
		t.Fatal(err)
	}
	c, err := checkNow(alice)
	if err != nil {
		t.Fatal(err)
	}
	if o := c.GetBaseOs(); len(o) != 2 || o[0].GetPreferred() || !o[1].GetPreferred() {
		t.Fatalf("offers %v", o)
	}
}

// A fetch reports its state, bytes and speed, and whether the file
// verified; a changed file is held for Verify and stage to refuse.
func TestAFetchReportsItsProgress(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	good := bin(t, b.sign, b.enc, full(release.ChannelProduction))
	b.mirrorFiles["sneakers-appliance-0.2.0-amd64.bin"] = good
	if err := setPolicy(t, alice, &osadminv1.UpgradePolicy{MirrorUrl: b.mirror.URL}); err != nil {
		t.Fatal(err)
	}
	f, err := alice.upgrade().FetchUpdate(context.Background(), connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "sneakers-appliance-0.2.0-amd64.bin"}))
	if err != nil {
		t.Fatal(err)
	}
	progress := func() *osadminv1.FetchProgress {
		g, _ := alice.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
		return g.Msg.GetFetchProgress()
	}
	p := progress()
	if p.GetState() != "done" || !p.GetVerified() || p.GetDoneBytes() != int64(len(good)) || p.GetTotalBytes() != int64(len(good)) || p.GetSource() != "mirror" ||
		p.GetUploadId() != f.Msg.GetUploadId() || p.GetTarget() != osadminv1.UpdateTarget_UPDATE_TARGET_BASE {
		t.Fatalf("progress %v", p)
	}
	if _, err := alice.upgrade().DiscardUpdate(context.Background(), connect.NewRequest(&osadminv1.DiscardUpdateRequest{UploadId: f.Msg.GetUploadId()})); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), good...)
	bad[len(bad)-1] ^= 0xff
	b.mirrorFiles["sneakers-appliance-0.2.0-amd64.bin"] = bad
	if _, err := alice.upgrade().FetchUpdate(context.Background(), connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "sneakers-appliance-0.2.0-amd64.bin"})); err != nil {
		t.Fatal(err)
	}
	if p := progress(); p.GetState() != "done" || p.GetVerified() || p.GetCode() != "UPGRADE_SIGNATURE" {
		t.Fatalf("a changed file: %v", p)
	}
	_, err = alice.upgrade().FetchUpdate(context.Background(), connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "sneakers-appliance-9.9.9-amd64.bin"}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_BUSY")
}

// A policy from before the source reads as one: a mirror URL is manual,
// direct alone the built-in list, neither none. The built-in list is
// walked in order, the lab mirrors before the release source.
func TestThePolicysSource(t *testing.T) {
	b := newBox(t, false, func(bx *box, o *osadmin.Options) { o.Upgrade.BuiltinMirrors = []string{bx.mirror.URL + "/missing"} })
	alice := b.browser()
	alice.signIn("alice")
	source := func() (string, bool) {
		g, _ := alice.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
		return g.Msg.GetPolicy().GetSource(), g.Msg.GetAirGapped()
	}
	if s, gapped := source(); s != osadmin.SourceNone || !gapped {
		t.Fatalf("a new box: %s %v", s, gapped)
	}
	for _, c := range []struct {
		pol  *osadminv1.UpgradePolicy
		want string
	}{
		{&osadminv1.UpgradePolicy{MirrorUrl: b.mirror.URL}, osadmin.SourceManual},
		{&osadminv1.UpgradePolicy{Direct: true}, osadmin.SourceBuiltIn},
		{&osadminv1.UpgradePolicy{}, osadmin.SourceNone},
	} {
		if err := setPolicy(t, alice, c.pol); err != nil {
			t.Fatal(err)
		}
		if s, _ := source(); s != c.want {
			t.Errorf("%v reads as %s, want %s", c.pol, s, c.want)
		}
	}
	symbolIn(t, setPolicy(t, alice, &osadminv1.UpgradePolicy{Source: osadmin.SourceManual}), connect.CodeInvalidArgument, "ACCESS_CONFIRM")
	symbolIn(t, setPolicy(t, alice, &osadminv1.UpgradePolicy{Source: "ftp"}), connect.CodeInvalidArgument, "ACCESS_CONFIRM")
	b.mirrorFiles["direct/latest/download/"+updatepkg.IndexName] = unitsIndex(t)
	if err := setPolicy(t, alice, &osadminv1.UpgradePolicy{Source: osadmin.SourceBuiltIn}); err != nil {
		t.Fatal(err)
	}
	c, err := checkNow(alice)
	if err != nil || c.GetSource() != "direct" {
		t.Fatalf("the built-in list: %v %v", c, err)
	}
	g, _ := alice.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if m := g.Msg.GetMirrorStatus(); m.GetSource() != osadmin.SourceBuiltIn || len(m.GetBuiltinUrls()) != 2 || m.GetBuiltinUrls()[0] != b.mirror.URL+"/missing" {
		t.Fatalf("the status names the list: %v", m)
	}
	if err := setPolicy(t, alice, &osadminv1.UpgradePolicy{Source: osadmin.SourceNone, MirrorUrl: b.mirror.URL}); err != nil {
		t.Fatal(err)
	}
	if s, gapped := source(); s != osadmin.SourceNone || !gapped {
		t.Fatalf("none with a URL kept: %s %v", s, gapped)
	}
}
