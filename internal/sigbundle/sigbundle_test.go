// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sigbundle_test

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
)

func TestMessageSignatureVerifies(t *testing.T) {
	k := testpki.ECDSA(t)
	data := []byte("release: 0.1.0\n")
	b, err := sigbundle.Parse(k.BlobBundle(t, data))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := sigbundle.ParsePublicKey(k.PublicPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(pub, sha256.Sum256(data)); err != nil {
		t.Fatal(err)
	}
}

func TestMessageSignatureRefusals(t *testing.T) {
	k, rogue := testpki.ECDSA(t), testpki.ECDSA(t)
	data := []byte("release: 0.1.0\n")
	b, _ := sigbundle.Parse(k.BlobBundle(t, data))
	rpub, _ := sigbundle.ParsePublicKey(rogue.PublicPEM)
	if err := b.Verify(rpub, sha256.Sum256(data)); !errors.Is(err, sigbundle.ErrBadSignature) {
		t.Fatalf("other key: %v", err)
	}
	pub, _ := sigbundle.ParsePublicKey(k.PublicPEM)
	if err := b.Verify(pub, sha256.Sum256([]byte("other"))); !errors.Is(err, sigbundle.ErrBadSignature) {
		t.Fatalf("other artifact: %v", err)
	}
}

func TestDSSEVerifiesAgainstSubjectDigest(t *testing.T) {
	k := testpki.ECDSA(t)
	d := sha256.Sum256([]byte("an OCI index"))
	b, err := sigbundle.Parse(k.DSSEBundle(t, "sneakers-os", d))
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := sigbundle.ParsePublicKey(k.PublicPEM)
	if err := b.Verify(pub, d); err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(pub, sha256.Sum256([]byte("another index"))); !errors.Is(err, sigbundle.ErrBadSignature) {
		t.Fatalf("other subject: %v", err)
	}
	rogue := testpki.ECDSA(t)
	rpub, _ := sigbundle.ParsePublicKey(rogue.PublicPEM)
	if err := b.Verify(rpub, d); !errors.Is(err, sigbundle.ErrBadSignature) {
		t.Fatalf("other key: %v", err)
	}
}

func TestParseRefusesMalformed(t *testing.T) {
	k := testpki.ECDSA(t)
	good := string(k.BlobBundle(t, []byte("x")))
	for name, doc := range map[string]string{
		"not json":      "{",
		"no media type": strings.Replace(good, "application/vnd.dev.sigstore.bundle.v0.3+json", "text/plain", 1),
		"no signature":  `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{}}`,
	} {
		if _, err := sigbundle.Parse([]byte(doc)); !errors.Is(err, sigbundle.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParsePublicKeyRequiresECDSA(t *testing.T) {
	if _, err := sigbundle.ParsePublicKey(testpki.SelfSigned(t, "db").PEM); err == nil {
		t.Fatal("a certificate is not a cosign public key")
	}
}
