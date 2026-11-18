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

// A production build carries the update feed's public key: without it the
// built-in source can't be read, so the pin is mandatory there; a lab build
// has no feed and needs none.
func TestAProductionBuildNeedsTheFeedKey(t *testing.T) {
	s := labSet(t)
	feed := string(testpki.ECDSA(t).PublicPEM)
	restore := release.SetForTest("production", s.rel, s.db, s.pk, s.kek)
	defer restore()
	if _, err := release.Load(); !codes.Is(err, codes.KitPinMissing) {
		t.Fatalf("a production build with no feed key: want KIT_PIN_MISSING, got %v", err)
	}
	restoreFeed := release.SetFeedForTest(feed, "", "")
	defer restoreFeed()
	p, err := release.Load()
	if err != nil || string(p.FeedKeyPEM) != feed || p.FeedKey2PEM != nil || !p.FeedKeyNotAfter.IsZero() {
		t.Fatalf("the feed key: %+v %v", p, err)
	}
	if p.Fingerprints().FeedKey != release.Fingerprint([]byte(feed)) || p.Fingerprints().FeedKey == "" {
		t.Fatalf("the feed key's fingerprint: %q", p.Fingerprints().FeedKey)
	}
}

func TestALabBuildNeedsNoFeedKey(t *testing.T) {
	s := labSet(t)
	restore := release.SetForTest("lab", s.rel, s.db, s.pk, s.kek)
	defer restore()
	p, err := release.Load()
	if err != nil || p.FeedKeyPEM != nil {
		t.Fatalf("a lab build: %+v %v", p, err)
	}
}

func TestAFeedKeyThatIsNotAKeyIsRefused(t *testing.T) {
	s := labSet(t)
	for name, pins := range map[string][3]string{
		"not PEM":              {"not a key", "", ""},
		"a certificate":        {s.db, "", ""},
		"a second not a key":   {string(testpki.ECDSA(t).PublicPEM), "junk", ""},
		"an expiry that isn't": {string(testpki.ECDSA(t).PublicPEM), "", "next tuesday"},
	} {
		t.Run(name, func(t *testing.T) {
			restore := release.SetForTest("production", s.rel, s.db, s.pk, s.kek)
			defer restore()
			restoreFeed := release.SetFeedForTest(pins[0], pins[1], pins[2])
			defer restoreFeed()
			if _, err := release.Load(); !codes.Is(err, codes.KitPinMissing) {
				t.Fatalf("want KIT_PIN_MISSING, got %v", err)
			}
		})
	}
}

// A second key and an expiry for the first serve a rotation.
func TestAFeedKeyRotationPinsLoad(t *testing.T) {
	s := labSet(t)
	a, b := string(testpki.ECDSA(t).PublicPEM), string(testpki.ECDSA(t).PublicPEM)
	restore := release.SetForTest("production", s.rel, s.db, s.pk, s.kek)
	defer restore()
	restoreFeed := release.SetFeedForTest(a, b, "2027-06-01T00:00:00Z")
	defer restoreFeed()
	p, err := release.Load()
	if err != nil || string(p.FeedKeyPEM) != a || string(p.FeedKey2PEM) != b || p.FeedKeyNotAfter.Year() != 2027 {
		t.Fatalf("the rotation pins: %+v %v", p, err)
	}
}
