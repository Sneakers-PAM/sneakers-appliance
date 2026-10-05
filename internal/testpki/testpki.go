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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
