// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package updatepkg_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

func ranged(minBase, maxBase string) updatepkg.Header {
	return updatepkg.Header{Version: "0.4.0", Arch: "amd64", Kind: updatepkg.KindProduct, MinBase: minBase, MaxBase: maxBase, Channel: release.ChannelLab}
}

func TestAProductBundleFitsItsBaseRange(t *testing.T) {
	h := ranged("0.2.0", "0.3.0")
	for _, ok := range []string{"0.2.0", "0.2.5", "0.3.0"} {
		if err := h.AppliesTo(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, out := range []string{"0.1.9", "0.3.1", "0.4.0"} {
		err := h.AppliesTo(out)
		if !codes.Is(err, codes.UpgradeProductBase) {
			t.Fatalf("%s: want UPGRADE_PRODUCT_BASE, got %v", out, err)
		}
		if d := codes.Describe(err); !strings.Contains(d, "0.2.0") || !strings.Contains(d, "0.3.0") || !strings.Contains(d, out) {
			t.Errorf("the refusal names the range and the running base: %s", d)
		}
	}
	if err := ranged("0.2.0", "").AppliesTo("9.0.0"); err != nil {
		t.Fatalf("no maximum: %v", err)
	}
	if err := ranged("0.2.0", "").AppliesTo("0.2.0-rc.1"); !codes.Is(err, codes.UpgradeProductBase) {
		t.Fatalf("a pre-release of the minimum is below it: %v", err)
	}
}

func TestABaseRangeIsCheckedWhenSealed(t *testing.T) {
	ks := newKeySet(t)
	for name, h := range map[string]updatepkg.Header{
		"bad minimum":         ranged("not a version", ""),
		"bad maximum":         ranged("0.2.0", "soon"),
		"maximum below":       ranged("0.3.0", "0.2.0"),
		"maximum alone":       ranged("", "0.3.0"),
		"range on a full":     {Version: "0.2.0", Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelLab, MinBase: "0.1.0"},
		"range on a patch":    {Version: "0.2.0-p1", Arch: "amd64", Kind: updatepkg.KindPatch, Channel: release.ChannelLab, Bases: []string{"0.2.0"}, MinBase: "0.1.0"},
		"neither bases nor a": ranged("", ""),
	} {
		if _, err := updatepkg.Encrypt(strings.NewReader("x"), h, ks.enc.Recipient(), &bytes.Buffer{}); !codes.Is(err, codes.UpgradeFormat) {
			t.Errorf("%s: want UPGRADE_FORMAT, got %v", name, err)
		}
	}
	if _, err := updatepkg.Encrypt(strings.NewReader("x"), ranged("0.2.0", "0.2.0"), ks.enc.Recipient(), &bytes.Buffer{}); err != nil {
		t.Fatalf("a one-version range: %v", err)
	}
}

// A bundle sealed before the range existed names its bases only, and still
// fits them; HasRange tells the caller to note it.
func TestAnOlderBundleWithBasesOnlyStillFits(t *testing.T) {
	h := productHeader(release.ChannelProduction, "0.2.0")
	if h.HasRange() {
		t.Fatal("a bases-only header has no range")
	}
	if err := h.AppliesTo("0.2.0"); err != nil {
		t.Fatal(err)
	}
	if !ranged("0.2.0", "").HasRange() {
		t.Fatal("a header with a minimum has a range")
	}
	b, err := ranged("0.2.0", "0.3.0").Marshal()
	if err != nil || !bytes.Contains(b, []byte(`"min_base":"0.2.0","max_base":"0.3.0"`)) {
		t.Fatalf("the header carries min_base and max_base: %s %v", b, err)
	}
	if b, _ := productHeader(release.ChannelProduction, "0.2.0").Marshal(); bytes.Contains(b, []byte("min_base")) {
		t.Fatalf("a bases-only header carries no range: %s", b)
	}
}

func TestTheOfferFollowsTheBaseRange(t *testing.T) {
	entry := func(v, minBase, maxBase string) updatepkg.IndexEntry {
		return updatepkg.EntryOf(updatepkg.Header{Version: v, Arch: "amd64", Kind: updatepkg.KindProduct, MinBase: minBase, MaxBase: maxBase, Channel: release.ChannelProduction}, 10)
	}
	idx := updatepkg.Index{Products: []updatepkg.IndexEntry{
		entry("0.3.0", "0.2.0", ""),
		entry("0.4.0", "0.2.0", "0.2.9"),
		entry("0.5.0", "0.3.0", ""),
	}}
	got := idx.Offer("amd64", release.ChannelProduction, "0.2.5", "")
	if len(got) != 2 || got[0].Version != "0.4.0" || got[1].Version != "0.3.0" {
		t.Fatalf("offer %+v", got)
	}
	if got[0].MinBase != "0.2.0" || got[0].MaxBase != "0.2.9" {
		t.Fatalf("the entry carries the range: %+v", got[0])
	}
}
