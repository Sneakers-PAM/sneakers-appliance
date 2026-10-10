// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package updatepkg_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

var (
	sumA = strings.Repeat("a", 64)
	sumB = strings.Repeat("b", 64)
	sumC = strings.Repeat("c", 64)
	sumD = strings.Repeat("d", 64)
)

func baseOS(v, ch string) updatepkg.Header {
	return updatepkg.Header{Unit: updatepkg.UnitBaseOS, Version: v, Commit: "1a2b3c4", Arch: "amd64", Kind: updatepkg.KindFull, Channel: ch}
}

func baseWeb(v, ch string) updatepkg.Header {
	return updatepkg.Header{Unit: updatepkg.UnitBaseWeb, Version: v, Commit: "1a2b3c4", Arch: "amd64", Kind: updatepkg.KindFull, Channel: ch}
}

func product(v, ch string) updatepkg.Header {
	return updatepkg.Header{Version: v, Arch: "amd64", Kind: updatepkg.KindProduct, Channel: ch}
}

func patch(target, base, ch string) updatepkg.Header {
	h := baseOS(target, ch)
	h.Kind, h.Bases, h.Method = updatepkg.KindPatch, []string{base}, updatepkg.MethodZstdPatch
	h.Base = &updatepkg.PatchBase{Version: base, RootSHA256: sumA, RootSize: 4096, UKISHA256: sumB}
	h.Target = &updatepkg.PatchTarget{Version: target, RootSHA256: sumC, UKISHA256: sumD}
	return h
}

// Each unit and kind has its own name: the version alone on production,
// lab-<build label> on lab, never the build date, time or commit (the
// header and the index carry those). The headers from before the units
// keep their names.
func TestEveryUnitHasItsOwnFileName(t *testing.T) {
	for want, h := range map[string]updatepkg.Header{
		"sneakers-appliance-baseOS-0.3.0-amd64.bin":                          baseOS("0.3.0", release.ChannelProduction),
		"sneakers-appliance-baseOS-0.1.0-rc.1-amd64.bin":                     baseOS("0.1.0-rc.1", release.ChannelProduction),
		"sneakers-appliance-baseWeb-0.3.2-amd64.bin":                         baseWeb("0.3.2", release.ChannelProduction),
		"sneakers-appliance-baseOS-patch-0.3.0-to-0.3.1-amd64.bin":           patch("0.3.1", "0.3.0", release.ChannelProduction),
		"sneakers-appliance-baseOS-patch-0.1.0-rc.1-to-0.1.0-rc.2-amd64.bin": patch("0.1.0-rc.2", "0.1.0-rc.1", release.ChannelProduction),
		"sneakers-appliance-baseOS-lab-n3-amd64.bin":                         baseOS("0.0.0-lab.20261010n3.r20261010105645-ga8df881", release.ChannelLab),
		"sneakers-appliance-baseOS-lab-m-amd64.bin":                          baseOS("0.0.0-lab.20261012m-g1a2b3c4", release.ChannelLab),
		"sneakers-appliance-baseWeb-lab-n3-amd64.bin":                        baseWeb("0.0.0-lab.20261010n3.r20261010105645-ga8df881", release.ChannelLab),
		"sneakers-appliance-baseOS-patch-lab-n2-to-n3-amd64.bin":             patch("0.0.0-lab.20261010n3.r20261010105645-ga8df881", "0.0.0-lab.20261010n2.r20261010093945-g1eef5f2", release.ChannelLab),
		"sneakers-appliance-0.3.0-amd64.bin":                                 {Version: "0.3.0", Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelProduction},
		"sneakers-product-0.2.0-amd64.bin":                                   productHeader(release.ChannelProduction, "0.2.0"),
		"sneakers-product-0.1.0-rc.1-amd64.bin":                              product("0.1.0-rc.1", release.ChannelProduction),
		"sneakers-product-lab-sneakers.10-amd64.bin":                         product("0.1.0-lab.sneakers.10", release.ChannelLab),
		"sneakers-product-lab-0.2.0-amd64.bin":                               productHeader(release.ChannelLab, "0.2.0"),
	} {
		if got := updatepkg.FileName(h); got != want {
			t.Errorf("got %s, want %s", got, want)
		}
		if !updatepkg.ValidFileName(want) {
			t.Errorf("%s isn't a valid name", want)
		}
	}
	if got := updatepkg.LegacyFileName(baseOS("0.0.0-lab.20261012m-g1a2b3c4", release.ChannelLab)); got != "sneakers-appliance-0.0.0-lab.20261012m-g1a2b3c4-amd64-LAB.bin" {
		t.Fatalf("the bridge name: %s", got)
	}
	for _, bad := range []string{"../sneakers-appliance-0.3.0-amd64.bin", "sneakers-appliance-baseOS-0.3.0-riscv64.bin", "sneakers-other-0.3.0-amd64.bin",
		"sneakers-appliance-baseOS-lab-n3/../x-amd64.bin", "sneakers-appliance-baseOS-lab--amd64.bin"} {
		if updatepkg.ValidFileName(bad) {
			t.Errorf("%s passed", bad)
		}
	}
}

// The names before the version-only scheme (the build's commit in every
// Base OS and Base Web name, -LAB on lab) are still what a box reads in an
// index from those builds: PreviousFileName gives them, and they stay
// valid file names.
func TestThePreviousNamesStillRead(t *testing.T) {
	for want, h := range map[string]updatepkg.Header{
		"sneakers-appliance-baseOS-0.3.0-g1a2b3c4-amd64.bin":                                                            baseOS("0.3.0", release.ChannelProduction),
		"sneakers-appliance-baseWeb-0.3.2-g1a2b3c4-amd64.bin":                                                           baseWeb("0.3.2", release.ChannelProduction),
		"sneakers-appliance-baseOS-patch-0.3.1-g1a2b3c4-from-0.3.0-amd64.bin":                                           patch("0.3.1", "0.3.0", release.ChannelProduction),
		"sneakers-appliance-baseOS-0.0.0-lab.20261012m-g1a2b3c4-amd64-LAB.bin":                                          baseOS("0.0.0-lab.20261012m-g1a2b3c4", release.ChannelLab),
		"sneakers-appliance-baseWeb-0.0.0-lab.20261012m-g1a2b3c4-amd64-LAB.bin":                                         baseWeb("0.0.0-lab.20261012m-g1a2b3c4", release.ChannelLab),
		"sneakers-product-0.2.0-amd64-LAB.bin":                                                                          productHeader(release.ChannelLab, "0.2.0"),
		"sneakers-appliance-baseOS-patch-0.0.0-lab.20261012m1-g1a2b3c4-from-0.0.0-lab.20261012m-g1a2b3c4-amd64-LAB.bin": patch("0.0.0-lab.20261012m1-g1a2b3c4", "0.0.0-lab.20261012m-g1a2b3c4", release.ChannelLab),
	} {
		if got := updatepkg.PreviousFileName(h); got != want {
			t.Errorf("got %s, want %s", got, want)
		}
		if !updatepkg.ValidFileName(want) {
			t.Errorf("%s isn't a valid name", want)
		}
		if !updatepkg.NamedFor(h, want) || !updatepkg.NamedFor(h, updatepkg.FileName(h)) || updatepkg.NamedFor(h, "sneakers-product-9.9.9-amd64.bin") {
			t.Errorf("%s: the names its header takes", want)
		}
	}
}

// A box reads an index from before the version-only names: an entry under
// its previous name is offered as before, and so is one under the new name.
func TestAnIndexWithThePreviousNamesIsOffered(t *testing.T) {
	n2, n3 := "0.0.0-lab.20261010n2.r20261010093945-g1eef5f2", "0.0.0-lab.20261010n3.r20261010105645-ga8df881"
	full, web, p := baseOS(n3, release.ChannelLab), baseWeb(n3, release.ChannelLab), patch(n3, n2, release.ChannelLab)
	prod := product("0.1.0-lab.sneakers.10", release.ChannelLab)
	prod.MinBase = n2
	for _, named := range []func(updatepkg.Header) string{updatepkg.PreviousFileName, updatepkg.FileName} {
		var idx updatepkg.Index
		for _, h := range []updatepkg.Header{full, web, p, prod} {
			h.Name = updatepkg.NameFor(h.Kind)
			if h.Unit == updatepkg.UnitBaseWeb {
				h.Name = updatepkg.NameWeb
			}
			if err := idx.AddFile(h, 10, named(h)); err != nil {
				t.Fatal(err)
			}
		}
		box := updatepkg.Box{Arch: "amd64", Channel: release.ChannelLab, BaseOS: n2, BaseWeb: n2}
		if got := idx.OfferBaseOS(box); len(got) != 2 || got[0].File != named(p) || got[1].File != named(full) {
			t.Errorf("Base OS offer %+v", got)
		}
		if got := idx.OfferBaseWeb(box); len(got) != 1 || got[0].File != named(web) {
			t.Errorf("Base Web offer %+v", got)
		}
		if got := idx.OfferProducts(box, ""); len(got) != 1 || got[0].File != named(prod) {
			t.Errorf("product offer %+v", got)
		}
	}
	var idx updatepkg.Index
	if err := idx.AddFile(full, 10, "sneakers-appliance-baseOS-lab-n9-amd64.bin"); err == nil {
		t.Fatal("a name another header gives was taken")
	}
}

// A Base Web package seals under its own header name, so a box from before
// the units refuses it at Verify; its unit, commit, epoch, requires and
// inputs survive the round trip.
func TestABaseWebPackageRoundTripsUnderItsOwnName(t *testing.T) {
	ks := newKeySet(t)
	h := baseWeb("0.3.2", release.ChannelProduction)
	h.Epoch, h.Inputs = 1, sumA
	h.Requires = map[updatepkg.Unit]updatepkg.Range{updatepkg.UnitBaseOS: {Min: "0.3.0", Before: "0.4.0"}}
	p := read(t, build(t, ks, h, []byte("pages")))
	if err := p.Verify(ks.sign.PublicPEM, release.ChannelProduction); err != nil {
		t.Fatal(err)
	}
	got := p.Header
	if got.Name != updatepkg.NameWeb || updatepkg.UnitOf(got) != updatepkg.UnitBaseWeb || got.Commit != "1a2b3c4" || got.Inputs != sumA || got.EpochOf() != 1 {
		t.Fatalf("header %+v", got)
	}
	if r := got.Requires[updatepkg.UnitBaseOS]; r.Min != "0.3.0" || r.Before != "0.4.0" {
		t.Fatalf("requires %+v", got.Requires)
	}
}

// A header from before the units reads as before: a sneakers-appliance one
// is the Base OS, a sneakers-product one the Product, both epoch 1.
func TestAHeaderWithoutTheNewFieldsReadsAsBefore(t *testing.T) {
	var h updatepkg.Header
	if err := json.Unmarshal([]byte(`{"format":1,"name":"sneakers-appliance","version":"0.2.0","arch":"amd64","kind":"full","channel":"lab"}`), &h); err != nil {
		t.Fatal(err)
	}
	if updatepkg.UnitOf(h) != updatepkg.UnitBaseOS || h.EpochOf() != 1 {
		t.Fatalf("%+v", h)
	}
	if updatepkg.UnitOf(productHeader(release.ChannelLab, "0.2.0")) != updatepkg.UnitProduct {
		t.Fatal("a product header is the Product")
	}
	b, err := fullHeader(release.ChannelLab).Marshal()
	if err != nil || bytes.Contains(b, []byte("unit")) || bytes.Contains(b, []byte("requires")) || bytes.Contains(b, []byte("epoch")) {
		t.Fatalf("an old-style header gains no fields: %s %v", b, err)
	}
}

func TestTheUnitsHeaderRules(t *testing.T) {
	ks := newKeySet(t)
	webPatch := baseWeb("0.3.2", release.ChannelLab)
	webPatch.Kind, webPatch.Bases = updatepkg.KindPatch, []string{"0.3.1"}
	osRequires := baseOS("0.3.0", release.ChannelLab)
	osRequires.Requires = map[updatepkg.Unit]updatepkg.Range{updatepkg.UnitBaseWeb: {Min: "0.3.0"}}
	webOnProduct := productHeader(release.ChannelLab, "0.2.0")
	webOnProduct.Unit = updatepkg.UnitBaseWeb
	backwards := baseWeb("0.3.2", release.ChannelLab)
	backwards.Requires = map[updatepkg.Unit]updatepkg.Range{updatepkg.UnitBaseOS: {Min: "0.4.0", Before: "0.3.0"}}
	badCommit := baseOS("0.3.0", release.ChannelLab)
	badCommit.Commit = "not-hex"
	badInputs := baseOS("0.3.0", release.ChannelLab)
	badInputs.Inputs = "short"
	wrongBase := patch("0.3.1", "0.3.0", release.ChannelLab)
	wrongBase.Bases = []string{"0.2.9"}
	noHash := patch("0.3.1", "0.3.0", release.ChannelLab)
	noHash.Base.RootSHA256 = ""
	wrongTarget := patch("0.3.1", "0.3.0", release.ChannelLab)
	wrongTarget.Target.Version = "0.3.2"
	method := patch("0.3.1", "0.3.0", release.ChannelLab)
	method.Method = "bsdiff"
	baseOnFull := baseOS("0.3.0", release.ChannelLab)
	baseOnFull.Base = &updatepkg.PatchBase{Version: "0.2.0"}
	for name, h := range map[string]updatepkg.Header{
		"a Base Web patch":            webPatch,
		"requires on a Base OS":       osRequires,
		"a product of unit Base Web":  webOnProduct,
		"a range that ends first":     backwards,
		"a commit that isn't hex":     badCommit,
		"an inputs digest too short":  badInputs,
		"a base outside bases":        wrongBase,
		"a base without its hash":     noHash,
		"a target of another version": wrongTarget,
		"another method":              method,
		"a base on a full release":    baseOnFull,
	} {
		if _, err := updatepkg.Encrypt(strings.NewReader("x"), h, ks.enc.Recipient(), &bytes.Buffer{}); !codes.Is(err, codes.UpgradeFormat) {
			t.Errorf("%s: want UPGRADE_FORMAT, got %v", name, err)
		}
	}
	for name, h := range map[string]updatepkg.Header{"a Base OS patch": patch("0.3.1", "0.3.0", release.ChannelLab), "a Base OS": baseOS("0.3.0", release.ChannelLab), "a Base Web": baseWeb("0.3.2", release.ChannelLab)} {
		if _, err := updatepkg.Encrypt(strings.NewReader("x"), h, ks.enc.Recipient(), &bytes.Buffer{}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	old := baseOS("0.3.1", release.ChannelLab)
	old.Kind, old.Bases = updatepkg.KindPatch, []string{"0.3.0"}
	if err := old.Applicable(); !codes.Is(err, codes.UpgradeFormat) {
		t.Fatalf("a patch without its hashes can't be rebuilt: %v", err)
	}
	if err := patch("0.3.1", "0.3.0", release.ChannelLab).Applicable(); err != nil {
		t.Fatal(err)
	}
}

// The default range is the same major.minor; a lab one takes the lab
// pre-releases.
func TestTheDefaultRangeIsTheSameMajorMinor(t *testing.T) {
	r := updatepkg.DefaultRange("0.3.2", release.ChannelProduction)
	if r.Min != "0.3.0" || r.Before != "0.4.0" || r.Text() != "0.3.0 to before 0.4.0" {
		t.Fatalf("%+v %s", r, r.Text())
	}
	for v, in := range map[string]bool{"0.3.0": true, "0.3.9": true, "0.2.9": false, "0.4.0": false, "1.3.0": false} {
		if r.Contains(v) != in {
			t.Errorf("%s: %v", v, !in)
		}
	}
	lab := updatepkg.DefaultRange("0.0.0-lab.20261012m-g1a2b3c4", release.ChannelLab)
	if !lab.Contains("0.0.0-lab.20261012m1-g7c41d2e") || !lab.Contains("0.0.0-lab.20261009l-g669baac") || lab.Contains("0.1.0-lab.1") {
		t.Fatalf("lab range %+v", lab)
	}
	if (updatepkg.Range{Min: "0.2.0"}).Text() != "0.2.0 or newer" {
		t.Fatal("an open range")
	}
}

// The compatibility matrix over every unit pair: a Base Web needs the Base
// OS its header names (or its own major.minor); the Base OS needs nothing;
// the product's range stays its own (AppliesTo).
func TestTheCompatibilityMatrix(t *testing.T) {
	web := baseWeb("0.4.0", release.ChannelProduction)
	web.Requires = map[updatepkg.Unit]updatepkg.Range{updatepkg.UnitBaseOS: {Min: "0.4.0", Before: "0.5.0"}}
	err := updatepkg.FitsBaseOS(web, "0.3.2", "0.4.1")
	if !codes.Is(err, codes.UpgradeCompat) {
		t.Fatalf("want UPGRADE_COMPAT, got %v", err)
	}
	want := "Base Web 0.4.0 needs Base OS 0.4.0 to before 0.5.0. This box runs Base OS 0.3.2. Install Base OS 0.4.x first; the mirror offers 0.4.1."
	if d := codes.Describe(err); !strings.HasSuffix(d, want) {
		t.Fatalf("the refusal says the fix: %s", d)
	}
	if err := updatepkg.FitsBaseOS(web, "0.4.3", ""); err != nil {
		t.Fatal(err)
	}
	if err := updatepkg.FitsBaseOS(baseWeb("0.3.2", release.ChannelProduction), "0.4.0", ""); !codes.Is(err, codes.UpgradeCompat) {
		t.Fatalf("the default range: %v", err)
	}
	if err := updatepkg.FitsBaseOS(baseWeb("0.3.2", release.ChannelProduction), "0.3.0", ""); err != nil {
		t.Fatalf("the default range: %v", err)
	}
	for _, h := range []updatepkg.Header{baseOS("9.0.0", release.ChannelProduction), productHeader(release.ChannelProduction, "0.1.0")} {
		if _, ok := h.NeedsBaseOS(); ok {
			t.Errorf("%s needs no Base OS range of its own here", h.Version)
		}
		if err := updatepkg.FitsBaseOS(h, "0.0.1", ""); err != nil {
			t.Errorf("%s: %v", h.Version, err)
		}
	}
}

func TestAnotherEpochIsRefused(t *testing.T) {
	h := baseOS("1.0.0", release.ChannelProduction)
	if err := updatepkg.CheckEpoch(h, updatepkg.BoxEpoch); err != nil {
		t.Fatalf("no epoch reads as 1: %v", err)
	}
	h.Epoch = 2
	err := updatepkg.CheckEpoch(h, updatepkg.BoxEpoch)
	if !codes.Is(err, codes.UpgradeEpoch) || !strings.Contains(codes.Describe(err), "epoch 2") {
		t.Fatalf("got %v", err)
	}
}

func indexOf(t *testing.T, hs ...updatepkg.Header) updatepkg.Index {
	t.Helper()
	var idx updatepkg.Index
	for _, h := range hs {
		if h.Name == "" {
			h.Name = updatepkg.NameFor(h.Kind)
			if h.Unit == updatepkg.UnitBaseWeb {
				h.Name = updatepkg.NameWeb
			}
		}
		idx.Add(h, 1000)
	}
	return idx
}

// Format 2 lists each unit; a box offers only what fits it.
func TestIndexFormat2OffersEachUnit(t *testing.T) {
	p := patch("0.3.1", "0.3.0", release.ChannelProduction)
	other := patch("0.3.1", "0.2.9", release.ChannelProduction)
	webFits := baseWeb("0.3.2", release.ChannelProduction)
	webNext := baseWeb("0.4.0", release.ChannelProduction)
	webEpoch := baseWeb("0.3.3", release.ChannelProduction)
	webEpoch.Epoch = 2
	idx := indexOf(t, baseOS("0.3.0", release.ChannelProduction), baseOS("0.3.1", release.ChannelProduction), p, other,
		webFits, webNext, webEpoch, baseWeb("0.3.1", release.ChannelProduction), productHeader(release.ChannelProduction, "0.3.0"))
	b, err := json.Marshal(idx)
	if err != nil || !bytes.Contains(b, []byte(`"format":2`)) || !bytes.Contains(b, []byte(`"baseOS":[`)) || !bytes.Contains(b, []byte(`"baseWeb":[`)) {
		t.Fatalf("index %s %v", b, err)
	}
	box := updatepkg.Box{Arch: "amd64", Channel: release.ChannelProduction, BaseOS: "0.3.0", BaseWeb: "0.3.1", RootSHA256: sumA}
	os := idx.OfferBaseOS(box)
	if len(os) != 2 || os[0].Kind != "patch" || os[0].Version != "0.3.1" || os[1].Kind != "full" || os[1].Version != "0.3.1" {
		t.Fatalf("Base OS offer %+v", os)
	}
	if os[0].BaseRootSHA256 != sumA || os[0].File != "sneakers-appliance-baseOS-patch-0.3.0-to-0.3.1-amd64.bin" {
		t.Fatalf("the patch entry %+v", os[0])
	}
	box.RootSHA256 = sumB
	if got := idx.OfferBaseOS(box); len(got) != 1 || got[0].Kind != "full" {
		t.Fatalf("a patch for another root image isn't offered: %+v", got)
	}
	web := idx.OfferBaseWeb(box)
	if len(web) != 1 || web[0].Version != "0.3.2" {
		t.Fatalf("Base Web offer %+v", web)
	}
	if e, need, ok := idx.UnfitBaseWeb(box); !ok || e.Version != "0.4.0" || need.Min != "0.4.0" {
		t.Fatalf("the Base Web that needs a newer Base OS: %+v %+v %v", e, need, ok)
	}
	box.BaseWeb = "0.3.2"
	if got := idx.OfferBaseWeb(box); len(got) != 0 {
		t.Fatalf("nothing newer than the running Base Web: %+v", got)
	}
	if got := idx.Offer("amd64", release.ChannelProduction, "0.3.0", ""); len(got) != 1 {
		t.Fatalf("products as before: %+v", got)
	}
}

// The bridge: the release that brings the units lists its Base OS full
// release a second time in the legacy base section, under the old name, so
// a box from before the units finds it; a box with the units offers it
// once, under its new name.
func TestTheBridgeEntryReachesBothKindsOfBox(t *testing.T) {
	m := baseOS("0.0.0-lab.20261012m-g1a2b3c4", release.ChannelLab)
	m.Name = updatepkg.Name
	idx := indexOf(t, m)
	idx.AddBridge(m, 1000)
	if len(idx.Base) != 1 || idx.Base[0].File != "sneakers-appliance-0.0.0-lab.20261012m-g1a2b3c4-amd64-LAB.bin" {
		t.Fatalf("legacy section %+v", idx.Base)
	}
	if got := idx.OfferBase("amd64", release.ChannelLab, "0.0.0-lab.20261009l-g669baac"); len(got) != 1 || got[0].File != idx.Base[0].File {
		t.Fatalf("the old box's offer %+v", got)
	}
	got := idx.OfferBaseOS(updatepkg.Box{Arch: "amd64", Channel: release.ChannelLab, BaseOS: "0.0.0-lab.20261009l-g669baac"})
	if len(got) != 1 || got[0].File != "sneakers-appliance-baseOS-lab-m-amd64.bin" {
		t.Fatalf("the new box's offer %+v", got)
	}
}

func TestTheReleaseOfAFileName(t *testing.T) {
	for name, want := range map[string]string{
		"sneakers-appliance-0.2.0-amd64.bin":                                   "0.2.0",
		"sneakers-product-0.2.0-amd64.bin":                                     "0.2.0",
		"sneakers-appliance-baseOS-0.3.0-g1a2b3c4-amd64.bin":                   "0.3.0",
		"sneakers-appliance-baseWeb-0.3.2-g1a2b3c4-arm64.bin":                  "0.3.2",
		"sneakers-appliance-baseOS-patch-0.3.1-g1a2b3c4-from-0.3.0-amd64.bin":  "0.3.1",
		"sneakers-appliance-baseOS-0.0.0-lab.20261012m-g1a2b3c4-amd64-LAB.bin": "0.0.0-lab.20261012m-g1a2b3c4",
		"sneakers-appliance-baseOS-0.1.0-rc.1-amd64.bin":                       "0.1.0-rc.1",
		"sneakers-appliance-baseWeb-0.1.0-arm64.bin":                           "0.1.0",
		"sneakers-appliance-baseOS-patch-0.1.0-rc.1-to-0.1.0-rc.2-amd64.bin":   "0.1.0-rc.2",
		"sneakers-product-0.1.0-rc.2-amd64.bin":                                "0.1.0-rc.2",
	} {
		if got, ok := updatepkg.ReleaseOf(name); !ok || got != want {
			t.Errorf("%s: %q %v", name, got, ok)
		}
	}
	// A lab name carries the build's label, not its version: only the index
	// says which release it is.
	for _, name := range []string{"index.html", "sneakers-appliance-baseOS-lab-n3-amd64.bin", "sneakers-product-lab-sneakers.10-amd64.bin"} {
		if _, ok := updatepkg.ReleaseOf(name); ok {
			t.Errorf("%s: not a release's name", name)
		}
	}
}

// A Base OS release, full or patch, names the Base Web it ships with
// (spec 7, Section 4.4): only a Base OS may, only a Base Web, and only by
// a release version. The index carries it, so the box can say so before
// the stage.
func TestABaseOSNamesTheBaseWebItShipsWith(t *testing.T) {
	ks := newKeySet(t)
	full := baseOS("0.3.1", release.ChannelLab)
	full.Includes = map[updatepkg.Unit]string{updatepkg.UnitBaseWeb: "0.3.1"}
	p := patch("0.3.1", "0.3.0", release.ChannelLab)
	p.Includes = map[updatepkg.Unit]string{updatepkg.UnitBaseWeb: "0.3.1"}
	for name, h := range map[string]updatepkg.Header{"a full Base OS": full, "a Base OS patch": p} {
		if _, err := updatepkg.Encrypt(strings.NewReader("x"), h, ks.enc.Recipient(), &bytes.Buffer{}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if got, ok := h.IncludesBaseWeb(); !ok || got != "0.3.1" {
			t.Errorf("%s: includes %q %v", name, got, ok)
		}
	}
	onWeb := baseWeb("0.3.1", release.ChannelLab)
	onWeb.Includes = map[updatepkg.Unit]string{updatepkg.UnitBaseWeb: "0.3.1"}
	product := baseOS("0.3.1", release.ChannelLab)
	product.Includes = map[updatepkg.Unit]string{updatepkg.UnitProduct: "0.1.0"}
	badVersion := baseOS("0.3.1", release.ChannelLab)
	badVersion.Includes = map[updatepkg.Unit]string{updatepkg.UnitBaseWeb: "latest"}
	for name, h := range map[string]updatepkg.Header{"a Base Web that includes one": onWeb, "a Base OS that includes a product": product, "a version that isn't one": badVersion} {
		if _, err := updatepkg.Encrypt(strings.NewReader("x"), h, ks.enc.Recipient(), &bytes.Buffer{}); !codes.Is(err, codes.UpgradeFormat) {
			t.Errorf("%s: want UPGRADE_FORMAT, got %v", name, err)
		}
	}
	if _, ok := baseOS("0.3.0", release.ChannelLab).IncludesBaseWeb(); ok {
		t.Fatal("a Base OS from before the rule names a Base Web")
	}
	idx := indexOf(t, full)
	if got := idx.BaseOS[0].Includes[updatepkg.UnitBaseWeb]; got != "0.3.1" {
		t.Fatalf("the index entry includes %q", got)
	}
}

// A production box following the rc channel is offered an rc of each
// unit; on the stable channel it isn't, as before.
func TestAnRCBoxIsOfferedRCs(t *testing.T) {
	idx := indexOf(t, baseOS("0.2.0-rc.2", release.ChannelProduction), patch("0.2.0-rc.2", "0.2.0-rc.1", release.ChannelProduction),
		baseWeb("0.2.0-rc.2", release.ChannelProduction))
	prod := productHeader(release.ChannelProduction, "0.2.0-rc.1")
	prod.Version = "0.2.0-rc.2"
	prod.Name = updatepkg.NameProduct
	idx.Add(prod, 1000)
	box := updatepkg.Box{Arch: "amd64", Channel: release.ChannelProduction, BaseOS: "0.2.0-rc.1", BaseWeb: "0.2.0-rc.1"}
	if got := idx.OfferBaseOS(box); len(got) != 0 {
		t.Fatalf("a stable box offered an rc Base OS: %+v", got)
	}
	if got := idx.OfferProducts(box, ""); len(got) != 0 {
		t.Fatalf("a stable box offered an rc product: %+v", got)
	}
	box.Prerelease = true
	os := idx.OfferBaseOS(box)
	if len(os) != 2 || os[0].Kind != "patch" || os[0].Version != "0.2.0-rc.2" || os[1].Kind != "full" {
		t.Fatalf("an rc box's Base OS offer %+v", os)
	}
	if got := idx.OfferProducts(box, "0.2.0-rc.1"); len(got) != 1 || got[0].Version != "0.2.0-rc.2" {
		t.Fatalf("an rc box's product offer %+v", got)
	}
	box.BaseOS = "0.2.0-rc.2"
	if got := idx.OfferBaseWeb(box); len(got) != 1 || got[0].Version != "0.2.0-rc.2" {
		t.Fatalf("an rc box's Base Web offer %+v", got)
	}
}
