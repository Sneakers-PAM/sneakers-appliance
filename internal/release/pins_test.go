// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package release_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
)

type pemSet struct{ rel, db, pk, kek string }

func labSet(t *testing.T) pemSet {
	t.Helper()
	return pemSet{
		rel: string(testpki.ECDSA(t).PublicPEM),
		db:  string(testpki.SelfSigned(t, "db").PEM),
		pk:  string(testpki.SelfSigned(t, "PK").PEM),
		kek: string(testpki.SelfSigned(t, "KEK").PEM),
	}
}

func TestLoadRefusesEmptyProductionPin(t *testing.T) {
	s := labSet(t)
	restore := release.SetForTest("production", "", s.db, s.pk, s.kek)
	defer restore()
	_, err := release.Load()
	if !codes.Is(err, codes.KitPinMissing) {
		t.Fatalf("want KIT_PIN_MISSING, got %v", err)
	}
}

func TestLoadRefusesEachEmptyPin(t *testing.T) {
	s := labSet(t)
	for name, set := range map[string]pemSet{
		"db":  {s.rel, "", s.pk, s.kek},
		"pk":  {s.rel, s.db, "", s.kek},
		"kek": {s.rel, s.db, s.pk, ""},
	} {
		t.Run(name, func(t *testing.T) {
			restore := release.SetForTest("lab", set.rel, set.db, set.pk, set.kek)
			defer restore()
			if _, err := release.Load(); !codes.Is(err, codes.KitPinMissing) {
				t.Fatalf("want KIT_PIN_MISSING, got %v", err)
			}
		})
	}
}

func TestLoadRefusesUnknownChannel(t *testing.T) {
	s := labSet(t)
	for _, ch := range []string{"", "staging", "Production"} {
		restore := release.SetForTest(ch, s.rel, s.db, s.pk, s.kek)
		_, err := release.Load()
		restore()
		if !codes.Is(err, codes.KitPinMissing) {
			t.Fatalf("channel %q: want KIT_PIN_MISSING, got %v", ch, err)
		}
	}
}

func TestLoadRefusesAPinThatIsNotPEM(t *testing.T) {
	s := labSet(t)
	restore := release.SetForTest("lab", s.rel, "not a certificate", s.pk, s.kek)
	defer restore()
	if _, err := release.Load(); !codes.Is(err, codes.KitPinMissing) {
		t.Fatalf("want KIT_PIN_MISSING, got %v", err)
	}
}

func TestLoadAcceptsLabChannel(t *testing.T) {
	s := labSet(t)
	restore := release.SetForTest("lab", s.rel, s.db, s.pk, s.kek)
	defer restore()
	p, err := release.Load()
	if err != nil || p.Channel != "lab" {
		t.Fatalf("got %+v %v", p, err)
	}
	if string(p.DBCertPEM) != s.db || string(p.ReleaseKeyPEM) != s.rel {
		t.Fatal("pins not returned as stamped")
	}
}

func TestFingerprintIsSHA256OfDER(t *testing.T) {
	s := labSet(t)
	restore := release.SetForTest("lab", s.rel, s.db, s.pk, s.kek)
	defer restore()
	p, err := release.Load()
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(s.db))
	sum := sha256.Sum256(blk.Bytes)
	if got := p.Fingerprints().DB; got != hex.EncodeToString(sum[:]) {
		t.Fatalf("db fingerprint %s", got)
	}
}
