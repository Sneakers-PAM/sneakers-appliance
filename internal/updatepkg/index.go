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
// Release. It lists the product bundles, the Base OS releases and the
// Base Web releases (format 2), and in its legacy base section the Base OS
// release a box from before the units can fetch.
const IndexName = "sneakers-product-index.json"

// IndexFormat is the index format this build writes: 2, with a list per
// unit.
const IndexFormat = 2

// maxIndex caps an index read from a mirror.
const maxIndex = 1 << 20

// Index lists the product bundles and base releases a source offers. It's
// a convenience for choosing one: nothing in it is trusted, since every
// .bin is verified when it's staged. An index from before the base
// section has none, and offers no base update.
type Index struct {
	// Format is 2 with the units' lists; absent before them.
	Format   int          `json:"format,omitempty"`
	Products []IndexEntry `json:"products"`
	// BaseOS and BaseWeb are the units' releases, full and patch.
	BaseOS  []IndexEntry `json:"baseOS,omitempty"`
	BaseWeb []IndexEntry `json:"baseWeb,omitempty"`
	// Base is the legacy section: base releases under the names a box from
	// before the units fetches.
	Base []IndexEntry `json:"base,omitempty"`
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
	// Epoch, Commit, Requires and Inputs are copied from the header.
	Epoch    int            `json:"epoch,omitempty"`
	Commit   string         `json:"commit,omitempty"`
	Requires map[Unit]Range `json:"requires,omitempty"`
	Inputs   string         `json:"inputs,omitempty"`
	// Includes is a Base OS release's Base Web, copied from the header.
	Includes map[Unit]string `json:"includes,omitempty"`
	// BaseRootSHA256 is a patch's base root image, so a box offers a patch
	// only for the exact root it runs.
	BaseRootSHA256 string `json:"base_root_sha256,omitempty"`
	File           string `json:"file"`
	Size           int64  `json:"size"`
}

// EntryOf is h's index entry for a sealed file of size bytes.
func EntryOf(h Header, size int64) IndexEntry {
	kind := string(h.Kind)
	if h.IsProduct() {
		kind = ""
	}
	e := IndexEntry{Kind: kind, Version: h.Version, Arch: h.Arch, Channel: h.Channel, Bases: slices.Clone(h.Bases), MinBase: h.MinBase, MaxBase: h.MaxBase, File: FileName(h), Size: size,
		Epoch: h.Epoch, Commit: h.Commit, Requires: h.Requires, Inputs: h.Inputs, Includes: h.Includes}
	if h.Base != nil {
		e.BaseRootSHA256 = h.Base.RootSHA256
	}
	return e
}

// header is the header an entry was copied from, as far as the index
// tells: enough to check its rules and its name.
func (e IndexEntry) header(u Unit) Header {
	k := Kind(e.Kind)
	if u == UnitProduct {
		k = KindProduct
	}
	h := Header{Format: Format, Version: e.Version, Arch: e.Arch, Kind: k, Bases: e.Bases, MinBase: e.MinBase, MaxBase: e.MaxBase, Channel: e.Channel,
		Epoch: e.Epoch, Commit: e.Commit, Requires: e.Requires, Inputs: e.Inputs, Includes: e.Includes}
	if u == UnitBaseOS || u == UnitBaseWeb {
		h.Unit = u
	}
	h.Name = nameOf(h)
	return h
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
// named the way its header names it (NamedFor). Newest first.
func (idx Index) Offer(arch, channel, base, installed string) []IndexEntry {
	return idx.offerProducts(arch, channel, base, installed, false)
}

// OfferProducts is Offer for b, which on a production box following the
// rc channel (b.Prerelease) takes pre-release bundles too.
func (idx Index) OfferProducts(b Box, installed string) []IndexEntry {
	return idx.offerProducts(b.Arch, b.Channel, b.BaseOS, installed, b.Prerelease)
}

func (idx Index) offerProducts(arch, channel, base, installed string, pre bool) []IndexEntry {
	var out []IndexEntry
	for _, e := range idx.Products {
		h := Header{Format: Format, Name: NameProduct, Version: e.Version, Arch: e.Arch, Kind: KindProduct, Bases: e.Bases, MinBase: e.MinBase, MaxBase: e.MaxBase, Channel: e.Channel}
		switch {
		case h.check() != nil, e.Arch != arch, e.Channel != channel, !NamedFor(h, e.File):
		case h.AppliesTo(base) != nil:
		case channel == release.ChannelProduction && !pre && semver.Prerelease("v"+e.Version) != "":
		case installed != "" && semver.Compare("v"+e.Version, "v"+installed) <= 0:
		default:
			out = append(out, e)
		}
	}
	slices.SortStableFunc(out, func(a, b IndexEntry) int { return semver.Compare("v"+b.Version, "v"+a.Version) })
	return slices.CompactFunc(out, func(a, b IndexEntry) bool { return a.Version == b.Version })
}

// Add puts h's entry in its section: products, baseOS, baseWeb, or for a
// header from before the units, base. The index is then format 2.
func (idx *Index) Add(h Header, size int64) {
	idx.add(h, EntryOf(h, size))
}

// AddFile is Add for a file published under the name file: the entry
// names it, so an index over files from before the version-only names
// lists them as they are. A name h isn't published under is refused.
func (idx *Index) AddFile(h Header, size int64, file string) error {
	if !NamedFor(h, file) {
		return codes.New(codes.UpgradeFormat, "%s isn't a name the %s %s header is published under (%s)", file, UnitOf(h).Title(), h.Version, FileName(h))
	}
	e := EntryOf(h, size)
	e.File = file
	idx.add(h, e)
	return nil
}

func (idx *Index) add(h Header, e IndexEntry) {
	idx.Format = IndexFormat
	switch {
	case h.IsProduct():
		idx.Products = append(idx.Products, e)
	case UnitOf(h) == UnitBaseWeb:
		idx.BaseWeb = append(idx.BaseWeb, e)
	case h.Unit == "":
		idx.Base = append(idx.Base, e)
	default:
		idx.BaseOS = append(idx.BaseOS, e)
	}
}

// AddBridge lists a Base OS full release in the legacy base section under
// its legacy name (LegacyFileName), for boxes from before the units: the
// release that bridges to the units publishes the same file under that
// name too (spec 7, Section 6).
func (idx *Index) AddBridge(h Header, size int64) {
	idx.Format = IndexFormat
	e := EntryOf(h, size)
	e.File = LegacyFileName(h)
	idx.Base = append(idx.Base, e)
}

// Box is what a box runs, for the units' offers. BaseWeb is the Base Web
// it serves (its built-in pages' version when none is installed);
// RootSHA256 is its running root image's, when it's known. Prerelease
// is set on a production box that follows the rc channel: it's offered
// pre-release units too.
type Box struct {
	Arch, Channel   string
	Epoch           int
	BaseOS, BaseWeb string
	RootSHA256      string
	Prerelease      bool
}

func (b Box) epoch() int {
	if b.Epoch == 0 {
		return BoxEpoch
	}
	return b.Epoch
}

// offerable is whether e, of unit u, is for b at all: its rules hold, its
// name is one its header gives (NamedFor), and it's b's architecture,
// channel and epoch, stable on a production box.
func (b Box) offerable(e IndexEntry, u Unit) (Header, bool) {
	h := e.header(u)
	switch {
	case h.check() != nil, e.Arch != b.Arch, e.Channel != b.Channel, !NamedFor(h, e.File):
	case h.EpochOf() != b.epoch():
	case b.Channel == release.ChannelProduction && !b.Prerelease && semver.Prerelease("v"+e.Version) != "":
	default:
		return h, true
	}
	return h, false
}

// OfferBaseOS is the Base OS releases b may stage: full or patch, newer
// than b.BaseOS, a patch only for the base b runs (and its root image,
// when both are known). The units' baseOS list comes first; the legacy
// base section adds what it alone lists. Newest first, a version's patch
// before its full release.
func (idx Index) OfferBaseOS(b Box) []IndexEntry {
	var out []IndexEntry
	seen := map[string]bool{}
	add := func(list []IndexEntry, u Unit) {
		for _, e := range list {
			h, ok := b.offerable(e, u)
			k := Kind(e.Kind)
			switch {
			case !ok, k != KindFull && k != KindPatch:
			case h.AppliesTo(b.BaseOS) != nil:
			case k == KindPatch && b.RootSHA256 != "" && e.BaseRootSHA256 != "" && e.BaseRootSHA256 != b.RootSHA256:
			case semver.Compare("v"+e.Version, "v"+b.BaseOS) <= 0:
			case seen[e.Version+"/"+e.Kind]:
			default:
				seen[e.Version+"/"+e.Kind] = true
				out = append(out, e)
			}
		}
	}
	add(idx.BaseOS, UnitBaseOS)
	add(idx.Base, "")
	slices.SortStableFunc(out, func(x, y IndexEntry) int {
		if c := semver.Compare("v"+y.Version, "v"+x.Version); c != 0 {
			return c
		}
		if x.Kind == y.Kind {
			return 0
		}
		if x.Kind == string(KindPatch) {
			return -1
		}
		return 1
	})
	return out
}

// OfferBaseWeb is the Base Web releases b may stage: newer than the Base
// Web b serves, and fitting the Base OS b runs. Newest first.
func (idx Index) OfferBaseWeb(b Box) []IndexEntry {
	var out []IndexEntry
	for _, e := range idx.BaseWeb {
		h, ok := b.offerable(e, UnitBaseWeb)
		switch {
		case !ok, h.Kind != KindFull:
		case FitsBaseOS(h, b.BaseOS, "") != nil:
		case b.BaseWeb != "" && semver.Compare("v"+e.Version, "v"+b.BaseWeb) <= 0:
		default:
			out = append(out, e)
		}
	}
	slices.SortStableFunc(out, func(x, y IndexEntry) int { return semver.Compare("v"+y.Version, "v"+x.Version) })
	return slices.CompactFunc(out, func(x, y IndexEntry) bool { return x.Version == y.Version })
}

// UnfitBaseWeb is the newest Base Web release for b's architecture,
// channel and epoch that doesn't fit the Base OS b runs, and the Base OS
// it needs; ok is false when there's none newer than b.BaseWeb. The
// Updates page names it, so an owner knows which Base OS comes first.
func (idx Index) UnfitBaseWeb(b Box) (IndexEntry, Range, bool) {
	var best IndexEntry
	var need Range
	found := false
	for _, e := range idx.BaseWeb {
		h, ok := b.offerable(e, UnitBaseWeb)
		if !ok || FitsBaseOS(h, b.BaseOS, "") == nil || (b.BaseWeb != "" && semver.Compare("v"+e.Version, "v"+b.BaseWeb) <= 0) {
			continue
		}
		if !found || semver.Compare("v"+e.Version, "v"+best.Version) > 0 {
			best, found = e, true
			need, _ = h.NeedsBaseOS()
		}
	}
	return best, need, found
}

// OfferBase is the base releases a box running base may stage from idx:
// full or patch, its architecture and channel, stable (no pre-release
// part; on a lab box every lab build counts), newer than running, a patch
// only for the base it names, and named the way its header names it. Newest
// first. Whether it fits the installed product's base range is the
// caller's to say.
func (idx Index) OfferBase(arch, channel, running string) []IndexEntry {
	var out []IndexEntry
	for _, e := range idx.Base {
		k := Kind(e.Kind)
		h := Header{Format: Format, Name: NameFor(k), Version: e.Version, Arch: e.Arch, Kind: k, Bases: e.Bases, Channel: e.Channel}
		switch {
		case k != KindFull && k != KindPatch:
		case h.check() != nil, e.Arch != arch, e.Channel != channel, !NamedFor(h, e.File):
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
