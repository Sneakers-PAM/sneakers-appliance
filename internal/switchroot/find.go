// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package switchroot

import (
	"strings"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bootcmd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Root slot labels and the install medium's volume label.
const (
	LabelRootA   = "sneakers-root-a"
	LabelRootB   = "sneakers-root-b"
	InstallLabel = "SNEAKERS_INSTALL"
)

// Partition is a block device the shim found: a GPT partition (Label is
// its GPT name, PartUUID its GUID) or a whole device carrying an ISO 9660
// volume (VolumeLabel).
type Partition struct {
	Device      string
	Label       string
	PartUUID    string
	VolumeLabel string
}

// Root is where the root comes from: a slot partition, or the root image
// file on the install medium.
type Root struct {
	Partition
	// ImageFile is set in install mode: the root image's path on the
	// mounted install medium.
	ImageFile string
}

// Install reports whether the root is the install medium's image file.
func (r Root) Install() bool { return r.ImageFile != "" }

// FindRoot picks the root for the signed command line: the slot whose
// PARTUUID is the first 128 bits of sneakers.roothash, in either slot; or,
// when no slot matches and an install medium is present, the root image on
// it. Anything else is ROOT_NOT_FOUND.
func FindRoot(cmdline string, parts []Partition) (Root, error) {
	p, err := bootcmd.Parse(cmdline)
	if err != nil {
		return Root{}, codes.Wrap(codes.RootNotFound, err)
	}
	want, err := bootcmd.SlotGUID(p.RootHash)
	if err != nil {
		return Root{}, codes.Wrap(codes.RootNotFound, err)
	}
	var match []Partition
	for _, part := range parts {
		if (part.Label == LabelRootA || part.Label == LabelRootB) && strings.EqualFold(part.PartUUID, want) {
			match = append(match, part)
		}
	}
	switch len(match) {
	case 1:
		return Root{Partition: match[0]}, nil
	case 0:
	default:
		return Root{}, codes.New(codes.RootNotFound, "%d root slots have PARTUUID %s; expected one", len(match), want)
	}
	if p.Version != "" {
		for _, part := range parts {
			if part.VolumeLabel == InstallLabel {
				return Root{Partition: part, ImageFile: "root-" + p.Version + ".img"}, nil
			}
		}
	}
	return Root{}, codes.New(codes.RootNotFound, "no root slot has PARTUUID %s, and there's no install medium", want)
}
