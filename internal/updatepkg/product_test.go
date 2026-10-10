// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package updatepkg_test

import (
	"bytes"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

func productHeader(channel string, bases ...string) updatepkg.Header {
	return updatepkg.Header{Version: "0.2.0", Arch: "amd64", Kind: updatepkg.KindProduct, Bases: bases, Channel: channel}
}

func TestAProductBundleRoundTripsUnderItsOwnName(t *testing.T) {
	ks := newKeySet(t)
	p := read(t, build(t, ks, productHeader(release.ChannelProduction, "0.2.0", "0.2.1"), []byte("k0s and its images")))
	if err := p.Verify(ks.sign.PublicPEM, release.ChannelProduction); err != nil {
		t.Fatal(err)
	}
	if p.Header.Name != updatepkg.NameProduct || !p.Header.IsProduct() {
		t.Fatalf("header %+v", p.Header)
	}
	var got bytes.Buffer
	if err := p.Decrypt(ks.enc, &got); err != nil || got.String() != "k0s and its images" {
		t.Fatalf("decrypt %q, %v", got.String(), err)
	}
	if fullHeader(release.ChannelLab).IsProduct() {
		t.Fatal("a full version counts as a product bundle")
	}
}

func TestAProductBundleNamesTheBasesItFits(t *testing.T) {
	ks := newKeySet(t)
	var ct bytes.Buffer
	if _, err := updatepkg.Encrypt(bytes.NewReader(nil), productHeader(release.ChannelLab), ks.enc.Recipient(), &ct); !codes.Is(err, codes.UpgradeFormat) {
		t.Fatalf("want UPGRADE_FORMAT for a bundle with no bases, got %v", err)
	}
	if _, err := updatepkg.Encrypt(bytes.NewReader(nil), productHeader(release.ChannelLab, "not a version"), ks.enc.Recipient(), &ct); !codes.Is(err, codes.UpgradeFormat) {
		t.Fatalf("want UPGRADE_FORMAT for a bad base, got %v", err)
	}
}

func TestAProductBundleFitsOnlyItsBases(t *testing.T) {
	h := productHeader(release.ChannelProduction, "0.2.0", "0.2.1")
	if err := h.AppliesTo("0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := h.AppliesTo("0.3.0"); !codes.Is(err, codes.UpgradeProductBase) {
		t.Fatalf("want UPGRADE_PRODUCT_BASE, got %v", err)
	}
}

func TestAHeaderWhoseNameAndKindDisagreeIsRefused(t *testing.T) {
	// A full version signed under the product name, and the reverse: the
	// name is signed, so neither can be passed off as the other.
	ks := newKeySet(t)
	for _, h := range []updatepkg.Header{
		{Format: updatepkg.Format, Name: updatepkg.NameProduct, Version: "0.2.0", Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelLab},
		{Format: updatepkg.Format, Name: updatepkg.Name, Version: "0.2.0", Arch: "amd64", Kind: updatepkg.KindProduct, Bases: []string{"0.2.0"}, Channel: release.ChannelLab},
	} {
		hdr, err := h.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := updatepkg.Seal(&out, hdr, ks.sign.BlobBundle(t, hdr), bytes.NewReader(nil)); err != nil {
			t.Fatal(err)
		}
		if err := read(t, out.Bytes()).Verify(ks.sign.PublicPEM, release.ChannelLab); !codes.Is(err, codes.UpgradeFormat) {
			t.Fatalf("%s %s: want UPGRADE_FORMAT, got %v", h.Name, h.Kind, err)
		}
	}
}

func TestAProductBundleHasItsOwnFileName(t *testing.T) {
	if got := updatepkg.FileName(productHeader(release.ChannelProduction, "0.2.0")); got != "sneakers-product-0.2.0-amd64.bin" {
		t.Fatal(got)
	}
	if got := updatepkg.FileName(productHeader(release.ChannelLab, "0.2.0")); got != "sneakers-product-lab-0.2.0-amd64.bin" {
		t.Fatal(got)
	}
}

func TestTheOfferIsStableFittingAndNewer(t *testing.T) {
	entry := func(v, ch string, bases ...string) updatepkg.IndexEntry {
		return updatepkg.EntryOf(updatepkg.Header{Version: v, Arch: "amd64", Kind: updatepkg.KindProduct, Bases: bases, Channel: ch}, 10)
	}
	idx := updatepkg.Index{Products: []updatepkg.IndexEntry{
		entry("0.2.0", release.ChannelProduction, "0.2.0"),
		entry("0.3.0", release.ChannelProduction, "0.2.0", "0.3.0"),
		entry("0.4.0-rc.1", release.ChannelProduction, "0.2.0"),
		entry("0.5.0", release.ChannelProduction, "0.5.0"),
		entry("0.6.0", release.ChannelLab, "0.2.0"),
		{Version: "0.7.0", Arch: "amd64", Channel: release.ChannelProduction, Bases: []string{"0.2.0"}, File: "../../etc/passwd"},
		{Version: "0.8.0", Arch: "arm64", Channel: release.ChannelProduction, Bases: []string{"0.2.0"}, File: "sneakers-product-0.8.0-arm64.bin"},
	}}
	got := idx.Offer("amd64", release.ChannelProduction, "0.2.0", "")
	if len(got) != 2 || got[0].Version != "0.3.0" || got[1].Version != "0.2.0" {
		t.Fatalf("first install offer %+v", got)
	}
	if got := idx.Offer("amd64", release.ChannelProduction, "0.2.0", "0.2.0"); len(got) != 1 || got[0].Version != "0.3.0" {
		t.Fatalf("upgrade offer %+v", got)
	}
	if got := idx.Offer("amd64", release.ChannelLab, "0.2.0", ""); len(got) != 1 || got[0].Version != "0.6.0" {
		t.Fatalf("lab offer %+v", got)
	}
}

func TestAnIndexOverAMegabyteIsRefused(t *testing.T) {
	if _, err := updatepkg.ReadIndex(bytes.NewReader(make([]byte, 2<<20))); !codes.Is(err, codes.UpgradeUpload) {
		t.Fatalf("got %v", err)
	}
}

// Base releases are offered from the index's base section: the box's
// architecture and channel, stable on a production box, newer than the
// running base, and a patch only for the base it names.
func TestTheBaseOfferIsStableFittingAndNewer(t *testing.T) {
	base := func(v, ch string, kind updatepkg.Kind, bases ...string) updatepkg.IndexEntry {
		return updatepkg.EntryOf(updatepkg.Header{Name: updatepkg.NameFor(kind), Version: v, Arch: "amd64", Kind: kind, Bases: bases, Channel: ch}, 10)
	}
	idx := updatepkg.Index{Base: []updatepkg.IndexEntry{
		base("0.1.0", release.ChannelProduction, updatepkg.KindFull),
		base("0.2.0", release.ChannelProduction, updatepkg.KindFull),
		base("0.2.1", release.ChannelProduction, updatepkg.KindPatch, "0.2.0"),
		base("0.2.2", release.ChannelProduction, updatepkg.KindPatch, "0.1.9"),
		base("0.3.0-rc.1", release.ChannelProduction, updatepkg.KindFull),
		base("0.4.0", release.ChannelLab, updatepkg.KindFull),
		{Version: "0.5.0", Arch: "amd64", Kind: "full", Channel: release.ChannelProduction, File: "../../etc/passwd"},
		{Version: "0.6.0", Arch: "arm64", Kind: "full", Channel: release.ChannelProduction, File: "sneakers-appliance-0.6.0-arm64.bin"},
		{Version: "0.7.0", Arch: "amd64", Kind: "product", Channel: release.ChannelProduction, Bases: []string{"0.1.0"}, File: "sneakers-product-0.7.0-amd64.bin"},
	}}
	got := idx.OfferBase("amd64", release.ChannelProduction, "0.1.0")
	if len(got) != 1 || got[0].Version != "0.2.0" || got[0].Kind != "full" || got[0].File != "sneakers-appliance-0.2.0-amd64.bin" {
		t.Fatalf("offer from 0.1.0 %+v", got)
	}
	if got := idx.OfferBase("amd64", release.ChannelProduction, "0.2.0"); len(got) != 1 || got[0].Version != "0.2.1" {
		t.Fatalf("offer from 0.2.0 %+v", got)
	}
	if got := idx.OfferBase("amd64", release.ChannelLab, "0.1.0"); len(got) != 1 || got[0].Version != "0.4.0" {
		t.Fatalf("lab offer %+v", got)
	}
}

// Today's product-only index still reads: it has no base section, so
// there's nothing to offer as a base update, and its products are offered
// as before.
func TestAProductOnlyIndexStillReads(t *testing.T) {
	old := `{"products":[{"version":"0.2.0","arch":"amd64","channel":"production","bases":["0.1.0"],"file":"sneakers-product-0.2.0-amd64.bin","size":10}]}`
	idx, err := updatepkg.ReadIndex(bytes.NewReader([]byte(old)))
	if err != nil {
		t.Fatal(err)
	}
	if got := idx.OfferBase("amd64", release.ChannelProduction, "0.1.0"); len(got) != 0 {
		t.Fatalf("base offer %+v", got)
	}
	if got := idx.Offer("amd64", release.ChannelProduction, "0.1.0", ""); len(got) != 1 {
		t.Fatalf("product offer %+v", got)
	}
}
