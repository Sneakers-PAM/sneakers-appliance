// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// TLSCA is a throwaway two-tier CA for TLS server certificates: a root and
// an intermediate that issues.
type TLSCA struct {
	Root, Intermediate       *x509.Certificate
	RootPEM, IntermediatePEM []byte
	rootKey, intKey          *ecdsa.PrivateKey
}

// NewTLSCA makes a root and an intermediate, valid for a year around now.
func NewTLSCA(t testing.TB) *TLSCA {
	t.Helper()
	ca := &TLSCA{rootKey: newP256(t), intKey: newP256(t)}
	now := time.Now()
	root := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: "Sneakers-PAM LAB ephemeral NOT FOR PRODUCTION TLS root"},
		NotBefore:             now.Add(-30 * 24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	ca.Root, ca.RootPEM = create(t, root, root, &ca.rootKey.PublicKey, ca.rootKey)
	inter := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: "Sneakers-PAM LAB ephemeral NOT FOR PRODUCTION TLS issuing"},
		NotBefore:             now.Add(-30 * 24 * time.Hour),
		NotAfter:              now.Add(300 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	ca.Intermediate, ca.IntermediatePEM = create(t, inter, ca.Root, &ca.intKey.PublicKey, ca.rootKey)
	return ca
}

// Leaf is an issued server certificate and, when the CA made the key, the
// key.
type Leaf struct {
	Cert   *x509.Certificate
	PEM    []byte
	Key    crypto.Signer
	KeyPEM []byte
}

// LeafOptions shape an issued certificate. Zero values give a P-256 server
// certificate valid from an hour ago for 90 days.
type LeafOptions struct {
	// Names are DNS names or IP addresses.
	Names               []string
	NotBefore, NotAfter time.Time
	// Public is the certificate's key; nil makes a P-256 key.
	Public crypto.PublicKey
	// ExtKeyUsage replaces server auth.
	ExtKeyUsage []x509.ExtKeyUsage
	IsCA        bool
}

// Issue signs a server certificate with the intermediate.
func (ca *TLSCA) Issue(t testing.TB, o LeafOptions) Leaf {
	t.Helper()
	var l Leaf
	pub := o.Public
	if pub == nil {
		k := newP256(t)
		l.Key, pub = k, &k.PublicKey
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		l.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	if o.NotBefore.IsZero() {
		o.NotBefore = time.Now().Add(-time.Hour)
	}
	if o.NotAfter.IsZero() {
		o.NotAfter = o.NotBefore.Add(90 * 24 * time.Hour)
	}
	eku := o.ExtKeyUsage
	if eku == nil {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		NotBefore:             o.NotBefore,
		NotAfter:              o.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           eku,
		IsCA:                  o.IsCA,
		BasicConstraintsValid: true,
	}
	for _, n := range o.Names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	if len(o.Names) > 0 {
		tmpl.Subject = pkix.Name{CommonName: o.Names[0]}
	}
	l.Cert, l.PEM = create(t, tmpl, ca.Intermediate, pub, ca.intKey)
	return l
}

// SignCSR issues a certificate for a PEM CSR with its own names.
func (ca *TLSCA) SignCSR(t testing.TB, csrPEM []byte, o LeafOptions) Leaf {
	t.Helper()
	blk, _ := pem.Decode(csrPEM)
	if blk == nil {
		t.Fatal("no CSR")
		return Leaf{}
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	o.Public = csr.PublicKey
	if o.Names == nil {
		o.Names = append(o.Names, csr.DNSNames...)
		for _, ip := range csr.IPAddresses {
			o.Names = append(o.Names, ip.String())
		}
	}
	return ca.Issue(t, o)
}

func newP256(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func create(t testing.TB, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, []byte) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
