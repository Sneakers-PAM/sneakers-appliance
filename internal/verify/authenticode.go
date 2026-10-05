// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/foxboron/go-uefi/authenticode"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Step 6 (amd64): the UKI and systemd-boot verify against the pinned db
// certificate, so a file the firmware would refuse is caught before any
// image is built.
func stepAuthenticode(_ context.Context, s *State) error {
	if s.Manifest.Spec.Arch != "amd64" {
		return nil
	}
	db, err := parseCert(s.Pins.DBCertPEM)
	if err != nil {
		return codes.Wrap(codes.KitPinMissing, err)
	}
	for _, name := range []string{s.Manifest.Spec.Boot.UKI.File, s.Manifest.Spec.Boot.Loader.File} {
		if err := s.authenticode(name, db); err != nil {
			return err
		}
	}
	return nil
}

func (s *State) authenticode(name string, db *x509.Certificate) (err error) {
	f, err := s.Layout.OpenBlob(s.Files[name])
	if err != nil {
		return codes.Wrap(codes.KitSourceUnreadable, err)
	}
	defer func() { _ = f.Close() }()
	// The parser reads attacker-supplied PE headers; a malformed file must
	// be a refusal, never a crash.
	defer func() {
		if r := recover(); r != nil {
			err = codes.New(codes.KitAuthenticode, "%s isn't a readable signed PE image (%v)", name, r)
		}
	}()
	pe, err := authenticode.Parse(f)
	if err != nil {
		return codes.New(codes.KitAuthenticode, "%s isn't a readable PE image: %v", name, err)
	}
	ok, err := pe.Verify(db)
	if err != nil || !ok {
		return codes.New(codes.KitAuthenticode, "%s doesn't verify against the pinned db certificate", name)
	}
	return nil
}

func parseCert(pemBytes []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no certificate in the pin")
	}
	return x509.ParseCertificate(blk.Bytes)
}
