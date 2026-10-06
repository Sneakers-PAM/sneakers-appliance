// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package efiauth_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/efiauth"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
)

var owner = [16]byte{1, 2, 3}

func TestAuthVerifiesWithItsSignerOnly(t *testing.T) {
	pk, kek, rogue := testpki.SelfSigned(t, "PK"), testpki.SelfSigned(t, "KEK"), testpki.SelfSigned(t, "rogue")
	esl := efiauth.X509List(owner, kek.Cert.Raw)
	a, err := efiauth.ParseAuth(pk.AuthFile(t, "KEK", esl))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Data, esl) {
		t.Fatal("the data after the header is the signature list")
	}
	if err := a.Verify("KEK", pk.Cert); err != nil {
		t.Fatal(err)
	}
	if err := a.Verify("KEK", rogue.Cert); !errors.Is(err, efiauth.ErrSignature) {
		t.Fatalf("rogue signer: %v", err)
	}
	if err := a.Verify("db", pk.Cert); !errors.Is(err, efiauth.ErrSignature) {
		t.Fatalf("another variable: %v", err)
	}
}

func TestAuthBindsTheData(t *testing.T) {
	kek, db, other := testpki.SelfSigned(t, "KEK"), testpki.SelfSigned(t, "db"), testpki.SelfSigned(t, "other")
	a, err := efiauth.ParseAuth(kek.AuthFile(t, "db", efiauth.X509List(owner, db.Cert.Raw)))
	if err != nil {
		t.Fatal(err)
	}
	a.Data = efiauth.X509List(owner, other.Cert.Raw)
	if err := a.Verify("db", kek.Cert); !errors.Is(err, efiauth.ErrSignature) {
		t.Fatalf("swapped data: %v", err)
	}
}

func TestParseAuthRefusesGarbage(t *testing.T) {
	for _, b := range [][]byte{nil, make([]byte, 39), bytes.Repeat([]byte{0xff}, 100)} {
		if _, err := efiauth.ParseAuth(b); !errors.Is(err, efiauth.ErrMalformed) {
			t.Fatalf("%d bytes: %v", len(b), err)
		}
	}
}

func TestSignatureListsRoundTrip(t *testing.T) {
	a, b := testpki.SelfSigned(t, "a"), testpki.SelfSigned(t, "b")
	lists := append(efiauth.X509List(owner, a.Cert.Raw), efiauth.X509List(owner, b.Cert.Raw)...)
	got, err := efiauth.ParseSignatureLists(lists)
	if err != nil || len(got) != 2 || !bytes.Equal(got[1].Data, b.Cert.Raw) || got[0].Type != "x509" || got[0].Owner != owner {
		t.Fatalf("%+v %v", got, err)
	}
	if got, err := efiauth.ParseSignatureLists(nil); err != nil || len(got) != 0 {
		t.Fatal("an empty list is valid (dbx at v0.1.0)")
	}
	if _, err := efiauth.ParseSignatureLists(lists[:len(lists)-3]); !errors.Is(err, efiauth.ErrMalformed) {
		t.Fatalf("truncated: %v", err)
	}
}

func TestParseGUID(t *testing.T) {
	g, err := efiauth.ParseGUID("8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err != nil || g != efiauth.GlobalVariable {
		t.Fatal(err)
	}
	want := [16]byte{0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c}
	if g != want {
		t.Fatalf("%x", g)
	}
}
