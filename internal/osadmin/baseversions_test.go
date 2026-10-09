// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"encoding/json"
	"testing"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// Updates offers base releases from the mirror's index the way it offers
// product bundles: newer than the running base (0.1.0 here), fitting
// (a patch only for its base) and on the box's channel, and it marks the
// ones outside the installed product's base range.
func TestBaseVersionsComeFromTheMirrorsIndex(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	_, err := alice.upgrade().ListBaseVersions(ctx, connect.NewRequest(&osadminv1.ListBaseVersionsRequest{}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_AIR_GAPPED")

	var idx updatepkg.Index
	for _, h := range []updatepkg.Header{
		{Name: updatepkg.NameFor(updatepkg.KindFull), Version: "0.2.0", Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelProduction},
		{Name: updatepkg.NameFor(updatepkg.KindPatch), Version: "0.1.1", Arch: "amd64", Kind: updatepkg.KindPatch, Bases: []string{"0.1.0"}, Channel: release.ChannelProduction},
		{Name: updatepkg.NameFor(updatepkg.KindPatch), Version: "0.1.2", Arch: "amd64", Kind: updatepkg.KindPatch, Bases: []string{"0.0.9"}, Channel: release.ChannelProduction},
		{Name: updatepkg.NameFor(updatepkg.KindFull), Version: "0.0.9", Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelProduction},
		{Name: updatepkg.NameFor(updatepkg.KindFull), Version: "0.3.0", Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelLab},
		{Name: updatepkg.NameProduct, Version: "0.4.0", Arch: "amd64", Kind: updatepkg.KindProduct, MinBase: "0.1.0", Channel: release.ChannelProduction},
	} {
		idx.Add(h, 100)
	}
	raw, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	b.mirrorFiles[updatepkg.IndexName] = raw
	pol := &osadminv1.UpgradePolicy{Mode: "manual", WindowStart: "02:00", WindowMinutes: 120, MirrorUrl: b.mirror.URL}
	if _, err := alice.upgrade().SetUpgradePolicy(ctx, connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol})); err != nil {
		t.Fatal(err)
	}
	list := func() *osadminv1.ListBaseVersionsResponse {
		t.Helper()
		l, err := alice.upgrade().ListBaseVersions(ctx, connect.NewRequest(&osadminv1.ListBaseVersionsRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return l.Msg
	}
	l := list()
	vs := l.GetVersions()
	if l.GetBaseVersion() != "0.1.0" || len(vs) != 2 || vs[0].GetVersion() != "0.2.0" || vs[1].GetVersion() != "0.1.1" {
		t.Fatalf("offered %v", l)
	}
	if v := vs[0]; v.GetKind() != "full" || v.GetFileName() != "sneakers-appliance-0.2.0-amd64.bin" || v.GetSource() != "mirror" || v.GetSize() != 100 || v.GetOutsideProductRange() {
		t.Fatalf("0.2.0 %v", v)
	}
	if v := vs[1]; v.GetKind() != "patch" || len(v.GetBases()) != 1 || v.GetBases()[0] != "0.1.0" {
		t.Fatalf("0.1.1 %v", v)
	}

	// With a product installed whose range ends at 0.1.5, 0.2.0 is still
	// listed, marked outside it.
	id, _ := alice.upload(t, productBinH(t, b.sign, b.enc, updatepkg.Header{Version: "0.2.0", Arch: "amd64", Kind: updatepkg.KindProduct, MinBase: "0.1.0", MaxBase: "0.1.5", Channel: release.ChannelProduction}))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	vs = list().GetVersions()
	if len(vs) != 2 || !vs[0].GetOutsideProductRange() || vs[0].GetProductRange() != "0.1.0 to 0.1.5" || vs[1].GetOutsideProductRange() {
		t.Fatalf("with the product installed %v", vs)
	}
}
