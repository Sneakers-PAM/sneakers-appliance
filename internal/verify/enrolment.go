// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/efiauth"
)

// Step 9 (amd64): the enrolment material holds exactly the pinned
// certificates, and each .auth is signed by the key the firmware will check
// it with: PK for PK and KEK, KEK for db.
func stepEnrolment(_ context.Context, s *State) error {
	if s.Manifest.Spec.Arch != "amd64" {
		return nil
	}
	certs := map[string]*x509.Certificate{}
	for name, p := range map[string][]byte{"PK": s.Pins.PKCertPEM, "KEK": s.Pins.KEKCertPEM, "db": s.Pins.DBCertPEM} {
		c, err := parseCert(p)
		if err != nil {
			return codes.Wrap(codes.KitPinMissing, err)
		}
		certs[name] = c
	}
	read := func(name string) ([]byte, error) {
		b, err := s.Layout.ReadBlob(s.Files[SecureBootKeyPrefix+name])
		if err != nil {
			return nil, digestOrUnreadable(err)
		}
		return b, nil
	}
	for _, v := range []struct{ name, signer string }{{"PK", "PK"}, {"KEK", "PK"}, {"db", "KEK"}} {
		esl, err := read(v.name + ".esl")
		if err != nil {
			return err
		}
		entries, err := efiauth.ParseSignatureLists(esl)
		if err != nil {
			return codes.New(codes.KitWrongSigner, "keys/%s.esl isn't a signature list: %v", v.name, err)
		}
		if len(entries) != 1 || entries[0].Type != "x509" || !bytes.Equal(entries[0].Data, certs[v.name].Raw) {
			return codes.New(codes.KitWrongSigner, "keys/%s.esl must hold exactly the pinned %s certificate; it holds %d entries", v.name, v.name, len(entries))
		}
		raw, err := read(v.name + ".auth")
		if err != nil {
			return err
		}
		a, err := efiauth.ParseAuth(raw)
		if err != nil {
			return codes.New(codes.KitWrongSigner, "keys/%s.auth isn't an authenticated variable: %v", v.name, err)
		}
		if !bytes.Equal(a.Data, esl) {
			return codes.New(codes.KitWrongSigner, "keys/%s.auth doesn't carry keys/%s.esl", v.name, v.name)
		}
		if err := a.Verify(v.name, certs[v.signer]); err != nil {
			if errors.Is(err, efiauth.ErrMalformed) {
				return codes.New(codes.KitWrongSigner, "keys/%s.auth has an unreadable signature: %v", v.name, err)
			}
			return codes.New(codes.KitWrongSigner, "keys/%s.auth isn't signed by the pinned %s", v.name, v.signer)
		}
	}
	dbx, err := read("dbx.esl")
	if err != nil {
		return err
	}
	if _, err := efiauth.ParseSignatureLists(dbx); err != nil {
		return codes.New(codes.KitWrongSigner, "keys/dbx.esl isn't a signature list: %v", err)
	}
	return nil
}
