// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package certstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// maxPEM bounds each uploaded field; minRSABits is the weakest RSA key
// accepted, in a CSR or an upload.
const (
	maxPEM     = 256 << 10
	minRSABits = 3072
)

// parseCerts reads every CERTIFICATE block in s, in order. field names the
// input for the error.
func parseCerts(field, s string) ([]*x509.Certificate, error) {
	if len(s) > maxPEM {
		return nil, codes.New(codes.TLSFormat, "the %s is larger than 256 KiB", field)
	}
	var out []*x509.Certificate
	rest := []byte(s)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, codes.New(codes.TLSFormat, "the %s holds a %s block, not a certificate", field, blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, codes.New(codes.TLSFormat, "a certificate in the %s doesn't parse: %v", field, err)
		}
		out = append(out, c)
	}
	if strings.TrimSpace(string(rest)) != "" && len(out) == 0 {
		return nil, codes.New(codes.TLSFormat, "the %s isn't PEM (it should start with -----BEGIN CERTIFICATE-----)", field)
	}
	return out, nil
}

// parseKey reads one private key: PKCS#8, SEC 1 (EC) or PKCS#1 (RSA).
func parseKey(s string) (crypto.Signer, error) {
	if len(s) > maxPEM {
		return nil, codes.New(codes.TLSFormat, "the private key is larger than 256 KiB")
	}
	blk, _ := pem.Decode([]byte(s))
	if blk == nil {
		return nil, codes.New(codes.TLSFormat, "the private key isn't PEM (it should start with -----BEGIN PRIVATE KEY-----)")
	}
	if blk.Type == "ENCRYPTED PRIVATE KEY" || blk.Headers["Proc-Type"] != "" {
		return nil, codes.New(codes.TLSFormat, "the private key is encrypted; upload it unencrypted, or as PKCS#12 with its password")
	}
	var k any
	var err error
	switch blk.Type {
	case "PRIVATE KEY":
		k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	case "EC PRIVATE KEY":
		k, err = x509.ParseECPrivateKey(blk.Bytes)
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	default:
		return nil, codes.New(codes.TLSFormat, "the private key is a %s block, not a private key", blk.Type)
	}
	if err != nil {
		return nil, codes.New(codes.TLSFormat, "the private key doesn't parse: %v", err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, codes.New(codes.TLSKeyType, "the private key isn't a signing key")
	}
	if err := checkKeyType(signer.Public()); err != nil {
		return nil, err
	}
	return signer, nil
}

// parsePKCS12 returns the key, the leaf and the rest of the chain.
func parsePKCS12(data []byte, password string) (crypto.Signer, *x509.Certificate, []*x509.Certificate, error) {
	if len(data) > maxPEM {
		return nil, nil, nil, codes.New(codes.TLSFormat, "the PKCS#12 file is larger than 256 KiB")
	}
	k, leaf, chain, err := pkcs12.DecodeChain(data, password)
	if errors.Is(err, pkcs12.ErrIncorrectPassword) {
		return nil, nil, nil, codes.New(codes.TLSFormat, "the PKCS#12 password is wrong")
	}
	if err != nil {
		return nil, nil, nil, codes.New(codes.TLSFormat, "the file isn't a PKCS#12 this box reads: %v", err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, nil, nil, codes.New(codes.TLSKeyType, "the PKCS#12 key isn't a signing key")
	}
	if err := checkKeyType(signer.Public()); err != nil {
		return nil, nil, nil, err
	}
	return signer, leaf, chain, nil
}

func marshalKey(k crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func checkKeyType(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < minRSABits {
			return codes.New(codes.TLSKeyType, "the key is RSA %d; it must be %d bits or more", k.N.BitLen(), minRSABits)
		}
		return nil
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() || k.Curve == elliptic.P384() {
			return nil
		}
		return codes.New(codes.TLSKeyType, "the key is ECDSA %s; it must be P-256 or P-384", k.Curve.Params().Name)
	}
	return codes.New(codes.TLSKeyType, "the key is %T; browsers need RSA or ECDSA P-256 or P-384", pub)
}

func keyTypeName(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	}
	return fmt.Sprintf("%T", pub)
}

func encodeCerts(cs []*x509.Certificate) string {
	var b strings.Builder
	for _, c := range cs {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.String()
}
