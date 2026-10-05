// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package sigbundle verifies a Sigstore bundle (v0.1 to v0.3, the format
// `cosign sign-blob --bundle` and cosign's OCI signatures write) against one
// pinned ECDSA public key.
//
// Trust comes only from the pinned key: there is no keyless path and no
// transparency-log dependency, so an offline site can verify. A bundle that
// also carries transparency-log entries is accepted on the strength of its
// signature; the entries are reported, not trusted.
package sigbundle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Media types of the bundle versions this package reads.
var mediaTypes = map[string]bool{
	"application/vnd.dev.sigstore.bundle+json;version=0.1": true,
	"application/vnd.dev.sigstore.bundle+json;version=0.2": true,
	"application/vnd.dev.sigstore.bundle+json;version=0.3": true,
	"application/vnd.dev.sigstore.bundle.v0.3+json":        true,
}

// MediaTypeV03 is the media type this package writes in fixtures and expects
// on an OCI signature layer.
const MediaTypeV03 = "application/vnd.dev.sigstore.bundle.v0.3+json"

// PayloadTypeInToto is the DSSE payload type of an in-toto statement.
const PayloadTypeInToto = "application/vnd.in-toto+json"

// ErrMalformed reports a bundle that can't be read; the caller treats it as
// no signature at all.
var ErrMalformed = errors.New("sigbundle: malformed bundle")

// ErrBadSignature reports a well-formed bundle whose signature doesn't verify
// with the given key, or that signs something else.
var ErrBadSignature = errors.New("sigbundle: signature does not verify")

// Bundle is the subset of the Sigstore bundle that key-based verification
// reads.
type Bundle struct {
	MediaType            string               `json:"mediaType"`
	VerificationMaterial VerificationMaterial `json:"verificationMaterial"`
	MessageSignature     *MessageSignature    `json:"messageSignature,omitempty"`
	DSSEEnvelope         *DSSEEnvelope        `json:"dsseEnvelope,omitempty"`
}

// VerificationMaterial names the key; its entries are informational here.
type VerificationMaterial struct {
	PublicKey   *PublicKeyHint    `json:"publicKey,omitempty"`
	TlogEntries []json.RawMessage `json:"tlogEntries,omitempty"`
}

// PublicKeyHint is the key hint a key-signed bundle carries.
type PublicKeyHint struct {
	Hint string `json:"hint,omitempty"`
}

// MessageSignature is a signature over an artifact's bytes.
type MessageSignature struct {
	MessageDigest MessageDigest `json:"messageDigest"`
	Signature     string        `json:"signature"`
}

// MessageDigest is the artifact digest a message signature covers.
type MessageDigest struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

// DSSEEnvelope is a signed in-toto statement.
type DSSEEnvelope struct {
	Payload     string          `json:"payload"`
	PayloadType string          `json:"payloadType"`
	Signatures  []DSSESignature `json:"signatures"`
}

// DSSESignature is one signature on a DSSE envelope.
type DSSESignature struct {
	Sig   string `json:"sig"`
	KeyID string `json:"keyid,omitempty"`
}

type statement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
}

// Parse reads a bundle.
func Parse(b []byte) (*Bundle, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var bd Bundle
	if err := dec.Decode(&bd); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if !mediaTypes[bd.MediaType] {
		return nil, fmt.Errorf("%w: media type %q", ErrMalformed, bd.MediaType)
	}
	if (bd.MessageSignature == nil) == (bd.DSSEEnvelope == nil) {
		return nil, fmt.Errorf("%w: want exactly one of messageSignature and dsseEnvelope", ErrMalformed)
	}
	return &bd, nil
}

// ParsePublicKey reads a PKIX PEM public key and requires ECDSA.
func ParsePublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("sigbundle: no PEM block in the public key")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sigbundle: parse the public key: %w", err)
	}
	ec, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("sigbundle: the public key is %T, want ECDSA", k)
	}
	return ec, nil
}

// Verify checks that bundle b is a signature by key over the artifact whose
// SHA-256 is digest. A message signature must name that digest and verify
// over it; a DSSE envelope must verify over its pre-authentication encoding
// and carry an in-toto statement with a subject of that digest.
func (b *Bundle) Verify(key *ecdsa.PublicKey, digest [sha256.Size]byte) error {
	if b.MessageSignature != nil {
		ms := b.MessageSignature
		if !strings.EqualFold(ms.MessageDigest.Algorithm, "SHA2_256") {
			return fmt.Errorf("%w: digest algorithm %q", ErrBadSignature, ms.MessageDigest.Algorithm)
		}
		named, err := base64.StdEncoding.DecodeString(ms.MessageDigest.Digest)
		if err != nil || !bytes.Equal(named, digest[:]) {
			return fmt.Errorf("%w: it signs a different artifact", ErrBadSignature)
		}
		sig, err := base64.StdEncoding.DecodeString(ms.Signature)
		if err != nil || !ecdsa.VerifyASN1(key, digest[:], sig) {
			return ErrBadSignature
		}
		return nil
	}
	env := b.DSSEEnvelope
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	pae := sha256.Sum256(PAE(env.PayloadType, payload))
	verified := false
	for _, s := range env.Signatures {
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err == nil && ecdsa.VerifyASN1(key, pae[:], sig) {
			verified = true
			break
		}
	}
	if !verified {
		return ErrBadSignature
	}
	if env.PayloadType != PayloadTypeInToto {
		return fmt.Errorf("%w: payload type %q", ErrBadSignature, env.PayloadType)
	}
	var st statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return fmt.Errorf("%w: statement: %v", ErrBadSignature, err)
	}
	want := hex.EncodeToString(digest[:])
	for _, sub := range st.Subject {
		if strings.EqualFold(sub.Digest["sha256"], want) {
			return nil
		}
	}
	return fmt.Errorf("%w: the statement names a different artifact", ErrBadSignature)
}

// PAE is the DSSE pre-authentication encoding.
func PAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}
