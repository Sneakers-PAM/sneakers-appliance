// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"debug/pe"
	"encoding/hex"
	"io"

	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/squashfs"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bootcmd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verity"
)

// Step 7: the root hash and offset in the signed command line are the
// manifest's, and the dm-verity tree recomputed over the whole root image
// gives that root hash.
func stepVerity(_ context.Context, s *State) error {
	cmd, err := s.signedCmdline()
	if err != nil {
		return err
	}
	p, err := bootcmd.Parse(cmd)
	if err != nil {
		return codes.Wrap(codes.KitVerityMismatch, err)
	}
	v := s.Manifest.Spec.Root.Verity
	if p.RootHash != v.RootHash || p.HashOffset != v.HashOffset {
		return codes.New(codes.KitVerityMismatch, "the signed command line names root hash %s at %d; appliance.yaml says %s at %d", p.RootHash, p.HashOffset, v.RootHash, v.HashOffset)
	}
	f, err := s.Layout.OpenBlob(s.Files[s.Manifest.Spec.Root.File])
	if err != nil {
		return codes.Wrap(codes.KitSourceUnreadable, err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return codes.Wrap(codes.KitSourceUnreadable, err)
	}
	got, err := verity.RootHash(f, st.Size(), p.HashOffset)
	if err != nil {
		return codes.New(codes.KitVerityMismatch, "%s: %v", s.Manifest.Spec.Root.File, err)
	}
	if hex.EncodeToString(got) != p.RootHash {
		return codes.New(codes.KitVerityMismatch, "%s has root hash %x; the signed command line says %s", s.Manifest.Spec.Root.File, got, p.RootHash)
	}
	return nil
}

// signedCmdline is the UKI's .cmdline section (amd64, already Authenticode
// checked) or cmdline.txt from the boot tarball (arm64, digest checked).
func (s *State) signedCmdline() (string, error) {
	if s.Manifest.Spec.Arch == "arm64" {
		b, err := s.arm64File("cmdline.txt")
		return string(b), err
	}
	f, err := s.Layout.OpenBlob(s.Files[s.Manifest.Spec.Boot.UKI.File])
	if err != nil {
		return "", codes.Wrap(codes.KitSourceUnreadable, err)
	}
	defer func() { _ = f.Close() }()
	pf, err := pe.NewFile(f)
	if err != nil {
		return "", codes.New(codes.KitVerityMismatch, "the UKI isn't a readable PE image: %v", err)
	}
	sec := pf.Section(".cmdline")
	if sec == nil {
		return "", codes.New(codes.KitVerityMismatch, "the UKI has no .cmdline section")
	}
	b, err := io.ReadAll(io.LimitReader(sec.Open(), 64<<10))
	if err != nil {
		return "", codes.New(codes.KitVerityMismatch, "the UKI's .cmdline can't be read: %v", err)
	}
	return string(b), nil
}

// Step 8: the verified root holds the verified release.yaml, and no k0s or
// images, which ship in the product bundle.
func stepBundle(_ context.Context, s *State) error {
	f, err := s.Layout.OpenBlob(s.Files[s.Manifest.Spec.Root.File])
	if err != nil {
		return codes.Wrap(codes.KitSourceUnreadable, err)
	}
	defer func() { _ = f.Close() }()
	sq, err := squashfs.Read(file.New(f, true), s.Manifest.Spec.Root.Verity.HashOffset, 0, 0)
	if err != nil {
		return codes.New(codes.KitBundleMismatch, "the root image isn't a readable SquashFS: %v", err)
	}
	defer func() { _ = sq.Close() }()
	return bundle.CheckRoot(sq, s.Release)
}
