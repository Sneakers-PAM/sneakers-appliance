// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package updatepkg

import (
	"encoding/json"
	"io"
	"slices"

	"golang.org/x/mod/semver"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
)

// IndexName is the index's file name on a mirror and on the GitHub
// Release. It lists the product bundles and, in its base section, the
// base releases.
const IndexName = "sneakers-product-index.json"

// maxIndex caps an index read from a mirror.
const maxIndex = 1 << 20

// Index lists the product bundles and base releases a source offers. It's
// a convenience for choosing one: nothing in it is trusted, since every
// .bin is verified when it's staged. An index from before the base
// section has none, and offers no base update.
type Index struct {
	Products []IndexEntry `json:"products"`
	Base     []IndexEntry `json:"base,omitempty"`
}

// IndexEntry is one bundle, copied from its header.
type IndexEntry struct {
	// Kind is full or patch for a base release; a product entry leaves it
	// out, as before the base section.
	Kind    string   `json:"kind,omitempty"`
	Version string   `json:"version"`
	Arch    string   `json:"arch"`
	Channel string   `json:"channel"`
	Bases   []string `json:"bases"`
	// MinBase and MaxBase are the bundle's base range, when it has one.
	MinBase string `json:"min_base,omitempty"`
	MaxBase string `json:"max_base,omitempty"`
	File    string `json:"file"`
	Size    int64  `json:"size"`
}

// EntryOf is h's index entry for a sealed file of size bytes.
func EntryOf(h Header, size int64) IndexEntry {
	kind := string(h.Kind)
	if h.IsProduct() {
		kind = ""
	}
	return IndexEntry{Kind: kind, Version: h.Version, Arch: h.Arch, Channel: h.Channel, Bases: slices.Clone(h.Bases), MinBase: h.MinBase, MaxBase: h.MaxBase, File: FileName(h), Size: size}
}

// ReadIndex parses an index of at most 1 MiB.
func ReadIndex(r io.Reader) (Index, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxIndex+1))
	if err != nil {
		return Index{}, codes.New(codes.UpgradeUpload, "the product index can't be read: %v", err)
	}
	if len(b) > maxIndex {
		return Index{}, codes.New(codes.UpgradeUpload, "the product index is over %d bytes", maxIndex)
	}
	var idx Index
	if err := json.Unmarshal(b, &idx); err != nil {
		return Index{}, codes.New(codes.UpgradeUpload, "the product index doesn't parse: %v", err)
	}
	return idx, nil
}

// Offer is what a box may install from idx: its architecture and channel,
// fitting base, stable (no pre-release part; on a lab box every lab build
// counts), newer than installed (empty before the first install), and
// named the way FileName names it. Newest first.
func (idx Index) Offer(arch, channel, base, installed string) []IndexEntry {
	var out []IndexEntry
	for _, e := range idx.Products {
		h := Header{Format: Format, Name: NameProduct, Version: e.Version, Arch: e.Arch, Kind: KindProduct, Bases: e.Bases, MinBase: e.MinBase, MaxBase: e.MaxBase, Channel: e.Channel}
		switch {
		case h.check() != nil, e.Arch != arch, e.Channel != channel, e.File != FileName(h):
		case h.AppliesTo(base) != nil:
		case channel == release.ChannelProduction && semver.Prerelease("v"+e.Version) != "":
		case installed != "" && semver.Compare("v"+e.Version, "v"+installed) <= 0:
		default:
			out = append(out, e)
		}
	}
	slices.SortStableFunc(out, func(a, b IndexEntry) int { return semver.Compare("v"+b.Version, "v"+a.Version) })
	return slices.CompactFunc(out, func(a, b IndexEntry) bool { return a.Version == b.Version })
}

// Add puts h's entry in its section: products or base.
func (idx *Index) Add(h Header, size int64) {
	if h.IsProduct() {
		idx.Products = append(idx.Products, EntryOf(h, size))
		return
	}
	idx.Base = append(idx.Base, EntryOf(h, size))
}

// OfferBase is the base releases a box running base may stage from idx:
// full or patch, its architecture and channel, stable (no pre-release
// part; on a lab box every lab build counts), newer than running, a patch
// only for the base it names, and named the way FileName names it. Newest
// first. Whether it fits the installed product's base range is the
// caller's to say.
func (idx Index) OfferBase(arch, channel, running string) []IndexEntry {
	var out []IndexEntry
	for _, e := range idx.Base {
		k := Kind(e.Kind)
		h := Header{Format: Format, Name: NameFor(k), Version: e.Version, Arch: e.Arch, Kind: k, Bases: e.Bases, Channel: e.Channel}
		switch {
		case k != KindFull && k != KindPatch:
		case h.check() != nil, e.Arch != arch, e.Channel != channel, e.File != FileName(h):
		case h.AppliesTo(running) != nil:
		case channel == release.ChannelProduction && semver.Prerelease("v"+e.Version) != "":
		case semver.Compare("v"+e.Version, "v"+running) <= 0:
		default:
			out = append(out, e)
		}
	}
	slices.SortStableFunc(out, func(a, b IndexEntry) int { return semver.Compare("v"+b.Version, "v"+a.Version) })
	return slices.CompactFunc(out, func(a, b IndexEntry) bool { return a.Version == b.Version })
}
