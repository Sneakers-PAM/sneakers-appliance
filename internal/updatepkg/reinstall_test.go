// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package updatepkg_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// The installed version is offered to reinstall when the index has it for
// this box, apart from the newer versions, a pre-release one included;
// another architecture, channel or a base it doesn't fit isn't.
func TestTheInstalledVersionIsOfferedToReinstall(t *testing.T) {
	idx := indexOf(t)
	for _, v := range []string{"0.2.0", "0.3.0", "0.4.0-rc.1"} {
		h := productHeader(release.ChannelProduction, "0.1.0")
		h.Version, h.Name = v, updatepkg.NameProduct
		idx.Add(h, 1000)
	}
	box := updatepkg.Box{Arch: "amd64", Channel: release.ChannelProduction, BaseOS: "0.1.0"}
	e, ok := idx.ReinstallProduct(box, "0.3.0")
	if !ok || e.Version != "0.3.0" || e.File == "" {
		t.Fatalf("reinstall offer %+v %v", e, ok)
	}
	if got := idx.OfferProducts(box, "0.3.0"); len(got) != 0 {
		t.Fatalf("the newer offers %+v", got)
	}
	if e, ok := idx.ReinstallProduct(box, "0.4.0-rc.1"); !ok || e.Version != "0.4.0-rc.1" {
		t.Fatalf("a pre-release installed: %+v %v", e, ok)
	}
	for _, b := range []updatepkg.Box{
		{Arch: "arm64", Channel: release.ChannelProduction, BaseOS: "0.1.0"},
		{Arch: "amd64", Channel: release.ChannelLab, BaseOS: "0.1.0"},
		{Arch: "amd64", Channel: release.ChannelProduction, BaseOS: "0.0.1"},
	} {
		if e, ok := idx.ReinstallProduct(b, "0.3.0"); ok {
			t.Fatalf("offered %+v to %+v", e, b)
		}
	}
	if _, ok := idx.ReinstallProduct(box, "0.2.5"); ok {
		t.Fatal("offered a version the index doesn't have")
	}
	if _, ok := idx.ReinstallProduct(box, ""); ok {
		t.Fatal("offered a reinstall with no product installed")
	}
}
