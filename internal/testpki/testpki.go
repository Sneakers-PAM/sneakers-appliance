// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package testpki makes throwaway certificates and keys for tests. Nothing it
// makes is ever written outside a test's temporary directory.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// Cert is a self-signed certificate with its key.
type Cert struct {
	Key  *rsa.PrivateKey
	Cert *x509.Certificate
	PEM  []byte
}

// SelfSigned returns an RSA-2048 self-signed certificate named
// "Sneakers-PAM LAB ephemeral NOT FOR PRODUCTION <role>".
func SelfSigned(t testing.TB, role string) Cert {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "Sneakers-PAM LAB ephemeral NOT FOR PRODUCTION " + role},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return Cert{Key: key, Cert: c, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// ECKey is an ECDSA P-256 key pair, the shape of a cosign key.
type ECKey struct {
	Key       *ecdsa.PrivateKey
	PublicPEM []byte
}

// ECDSA returns a fresh P-256 key with its public key as a PKIX PEM block.
func ECDSA(t testing.TB) ECKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return ECKey{Key: key, PublicPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})}
}

// BlobBundle signs data as `cosign sign-blob --key --bundle` does: a v0.3
// bundle with a message signature over the SHA-256 of data.
func (k ECKey) BlobBundle(t testing.TB, data []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, k.Key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return mustJSON(t, map[string]any{
		"mediaType":            "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{"publicKey": map[string]string{"hint": "lab"}},
		"messageSignature": map[string]any{
			"messageDigest": map[string]string{"algorithm": "SHA2_256", "digest": base64.StdEncoding.EncodeToString(sum[:])},
			"signature":     base64.StdEncoding.EncodeToString(sig),
		},
	})
}

// DSSEBundle signs an in-toto statement whose subject is the artifact with
// SHA-256 digest, the shape cosign uses for an OCI artifact.
func (k ECKey) DSSEBundle(t testing.TB, name string, digest [sha256.Size]byte) []byte {
	t.Helper()
	payload := mustJSON(t, map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": name, "digest": map[string]string{"sha256": hex.EncodeToString(digest[:])}}},
		"predicateType": "https://sigstore.dev/cosign/sign/v1",
		"predicate":     map[string]any{},
	})
	const pt = "application/vnd.in-toto+json"
	pae := sha256.Sum256([]byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(pt), pt, len(payload), payload)))
	sig, err := ecdsa.SignASN1(rand.Reader, k.Key, pae[:])
	if err != nil {
		t.Fatal(err)
	}
	return mustJSON(t, map[string]any{
		"mediaType":            "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{"publicKey": map[string]string{"hint": "lab"}},
		"dsseEnvelope": map[string]any{
			"payload":     base64.StdEncoding.EncodeToString(payload),
			"payloadType": pt,
			"signatures":  []any{map[string]string{"sig": base64.StdEncoding.EncodeToString(sig)}},
		},
	})
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
