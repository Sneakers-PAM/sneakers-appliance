// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package secureboot

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/efiauth"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
)

// State is the firmware's Secure Boot state.
type State struct {
	// Supported: the firmware exposes SecureBoot or SetupMode.
	Supported bool
	// SetupMode: no PK; the firmware accepts new keys.
	SetupMode bool
	// Enforcing: SecureBoot reads 1.
	Enforcing bool
	// OrgOnly: PK, KEK and db hold exactly the pinned org certificates.
	OrgOnly bool
}

// Read reads the state. A nil store means efivarfs isn't mounted, which is
// an error, never a silent "no Secure Boot". Firmware with neither
// SecureBoot nor SetupMode has no Secure Boot. SetupMode alone (some
// firmware drops SecureBoot in Setup Mode) still means it's supported.
// OrgOnly is checked against pins when given.
func Read(v Vars, pins *release.Pins) (State, error) {
	if v == nil {
		return State{}, codes.New(codes.SBNoEfivarfs, "efivarfs isn't mounted; can't tell whether this firmware has Secure Boot")
	}
	var st State
	sb, sbErr := flag(v, "SecureBoot")
	sm, smErr := flag(v, "SetupMode")
	for _, err := range []error{sbErr, smErr} {
		if err != nil && !errors.Is(err, ErrNotFound) {
			return State{}, codes.Wrap(codes.SBNoEfivarfs, err)
		}
	}
	st.Supported = sbErr == nil || smErr == nil
	st.Enforcing = sbErr == nil && sb
	st.SetupMode = smErr == nil && sm
	if pins != nil && st.Supported && !st.SetupMode {
		ok, err := OrgOnly(v, *pins)
		if err != nil {
			return State{}, err
		}
		st.OrgOnly = ok
	}
	return st, nil
}

func flag(v Vars, name string) (bool, error) {
	_, data, err := v.Get(name, GlobalGUID)
	if err != nil {
		return false, err
	}
	return len(data) > 0 && data[0] == 1, nil
}

// OrgOnly reports whether PK, KEK and db each hold exactly one entry, the
// pinned certificate. Anything else (a vendor key left in db, a Microsoft
// KEK) is not org-only.
func OrgOnly(v Vars, pins release.Pins) (bool, error) {
	for _, c := range []struct {
		name string
		pem  []byte
	}{{"PK", pins.PKCertPEM}, {"KEK", pins.KEKCertPEM}, {"db", pins.DBCertPEM}} {
		want, err := certDER(c.pem)
		if err != nil {
			return false, codes.Wrap(codes.KitPinMissing, err)
		}
		_, data, err := v.Get(c.name, vendorFor(c.name))
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, codes.Wrap(codes.SBNoEfivarfs, err)
		}
		entries, err := efiauth.ParseSignatureLists(data)
		if err != nil || len(entries) != 1 || entries[0].Type != "x509" || !bytes.Equal(entries[0].Data, want) {
			return false, nil
		}
	}
	return true, nil
}

func certDER(p []byte) ([]byte, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, errors.New("no certificate in the pin")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	return c.Raw, nil
}
