// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Step 6 on arm64, standing in for Authenticode and the enrolment material:
// the boot tarball holds exactly the files appliance.yaml lists, each with
// its digest. The tarball's own digest was checked in step 5.
func stepArm64Boot(_ context.Context, s *State) error {
	if s.Manifest.Spec.Arch != "arm64" {
		return nil
	}
	want := s.Manifest.Spec.Boot.Arm64.Files
	seen := map[string]bool{}
	err := s.walkArm64(func(name string, r io.Reader) error {
		sum, ok := want[name]
		if !ok {
			return codes.New(codes.KitDigestMismatch, "the boot tarball holds %s, which appliance.yaml doesn't list", name)
		}
		if seen[name] {
			return codes.New(codes.KitDigestMismatch, "the boot tarball holds %s twice", name)
		}
		seen[name] = true
		h := sha256.New()
		if _, err := io.Copy(h, r); err != nil {
			return codes.Wrap(codes.KitSourceUnreadable, err)
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != sum {
			return codes.New(codes.KitDigestMismatch, "boot file %s has SHA-256 %s; appliance.yaml says %s", name, got, sum)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for name := range want {
		if !seen[name] {
			return codes.New(codes.KitDigestMismatch, "appliance.yaml lists boot file %s, which the tarball doesn't hold", name)
		}
	}
	return nil
}

func (s *State) walkArm64(fn func(name string, r io.Reader) error) error {
	f, err := s.Layout.OpenBlob(s.Files[s.Manifest.Spec.Boot.Arm64.File])
	if err != nil {
		return codes.Wrap(codes.KitSourceUnreadable, err)
	}
	defer func() { _ = f.Close() }()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return codes.New(codes.KitDigestMismatch, "the boot tarball isn't readable: %v", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		if err := fn(path.Clean(h.Name), tr); err != nil {
			return err
		}
	}
}

// arm64File reads one file of the boot tarball.
func (s *State) arm64File(name string) ([]byte, error) {
	var out []byte
	found := false
	err := s.walkArm64(func(n string, r io.Reader) error {
		if n != name {
			return nil
		}
		b, err := io.ReadAll(io.LimitReader(r, 64<<10))
		out, found = b, true
		return err
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, codes.New(codes.KitVerityMismatch, "the boot tarball has no %s", name)
	}
	return out, nil
}
