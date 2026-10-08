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

// IndexName is the product index's file name on a mirror and on the
// GitHub Release.
const IndexName = "sneakers-product-index.json"

// maxIndex caps an index read from a mirror.
const maxIndex = 1 << 20

// Index lists the product bundles a source offers. It's a convenience for
// choosing one: nothing in it is trusted, since every bundle is verified
// when it's staged.
type Index struct {
	Products []IndexEntry `json:"products"`
}

// IndexEntry is one bundle, copied from its header.
type IndexEntry struct {
	Version string   `json:"version"`
	Arch    string   `json:"arch"`
	Channel string   `json:"channel"`
	Bases   []string `json:"bases"`
	File    string   `json:"file"`
	Size    int64    `json:"size"`
}

// EntryOf is h's index entry for a sealed file of size bytes.
func EntryOf(h Header, size int64) IndexEntry {
	return IndexEntry{Version: h.Version, Arch: h.Arch, Channel: h.Channel, Bases: slices.Clone(h.Bases), File: FileName(h), Size: size}
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
		h := Header{Format: Format, Name: NameProduct, Version: e.Version, Arch: e.Arch, Kind: KindProduct, Bases: e.Bases, Channel: e.Channel}
		switch {
		case h.check() != nil, e.Arch != arch, e.Channel != channel, e.File != FileName(h):
		case !slices.Contains(e.Bases, base):
		case channel == release.ChannelProduction && semver.Prerelease("v"+e.Version) != "":
		case installed != "" && semver.Compare("v"+e.Version, "v"+installed) <= 0:
		default:
			out = append(out, e)
		}
	}
	slices.SortStableFunc(out, func(a, b IndexEntry) int { return semver.Compare("v"+b.Version, "v"+a.Version) })
	return slices.CompactFunc(out, func(a, b IndexEntry) bool { return a.Version == b.Version })
}
