// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
)

// Step 2: the artifact (its index digest) is signed by the pinned release key.
func stepArtifactSignature(_ context.Context, s *State) error {
	key, err := sigbundle.ParsePublicKey(s.Pins.ReleaseKeyPEM)
	if err != nil {
		return codes.Wrap(codes.KitPinMissing, err)
	}
	refs, err := s.Layout.Referrers(s.Digest, SignatureArtifactType)
	if err != nil {
		return codes.Wrap(codes.KitSourceUnreadable, err)
	}
	var want [sha256.Size]byte
	raw, err := hex.DecodeString(s.Digest.Encoded())
	if err != nil || len(raw) != sha256.Size {
		return codes.New(codes.KitSourceUnreadable, "the artifact digest %s isn't SHA-256", s.Digest)
	}
	copy(want[:], raw)
	parsed := 0
	for _, ref := range refs {
		for _, layer := range ref.Manifest.Layers {
			b, err := s.Layout.ReadBlob(layer)
			if err != nil {
				continue
			}
			bd, err := sigbundle.Parse(b)
			if err != nil {
				continue
			}
			parsed++
			if bd.Verify(key, want) == nil {
				s.Opts.Logger.Info("verify: artifact signature verified", log.F("tlog_entries", len(bd.VerificationMaterial.TlogEntries)))
				return nil
			}
		}
	}
	if parsed == 0 {
		return codes.New(codes.KitSigMissing, "the artifact %s has no signature", s.Digest)
	}
	return codes.New(codes.KitWrongSigner, "the artifact %s is signed, but not by the pinned release key", s.Digest)
}

// Step 4: release.yaml is signed by the same key, and its digest is the one
// appliance.yaml names.
func stepRelease(_ context.Context, s *State) error {
	key, err := sigbundle.ParsePublicKey(s.Pins.ReleaseKeyPEM)
	if err != nil {
		return codes.Wrap(codes.KitPinMissing, err)
	}
	relDesc, ok := s.Files[FileRelease]
	if !ok {
		return codes.New(codes.KitDigestMismatch, "the artifact carries no %s", FileRelease)
	}
	rel, err := s.Layout.ReadBlob(relDesc)
	if err != nil {
		return digestOrUnreadable(err)
	}
	sigDesc, ok := s.Files[FileReleaseSig]
	if !ok {
		return codes.New(codes.KitSigMissing, "%s has no signature", FileRelease)
	}
	sigBytes, err := s.Layout.ReadBlob(sigDesc)
	if err != nil {
		return digestOrUnreadable(err)
	}
	bd, err := sigbundle.Parse(sigBytes)
	if err != nil {
		return codes.New(codes.KitSigMissing, "%s has no readable signature: %v", FileRelease, err)
	}
	sum := sha256.Sum256(rel)
	if err := bd.Verify(key, sum); err != nil {
		if errors.Is(err, sigbundle.ErrMalformed) {
			return codes.New(codes.KitSigMissing, "%s has no readable signature: %v", FileRelease, err)
		}
		return codes.New(codes.KitWrongSigner, "%s is signed, but not by the pinned release key", FileRelease)
	}
	if got := hex.EncodeToString(sum[:]); "sha256:"+got != s.Manifest.Spec.Release.Digest {
		return codes.New(codes.KitDigestMismatch, "%s has digest sha256:%s; appliance.yaml says %s", FileRelease, got, s.Manifest.Spec.Release.Digest)
	}
	s.Release = rel
	return nil
}
