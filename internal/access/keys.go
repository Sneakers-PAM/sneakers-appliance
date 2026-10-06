// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package access holds the appliance's access store: the admins, their SSH
// login keys, the recovery keys backups are encrypted to and the elevation
// policy, with the invariants checked on every write (spec 2, Sections 2.4,
// 2.5, 4.1 and 4.2).
package access

import (
	"bytes"
	"crypto/rsa"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// MinRSABits is the smallest RSA modulus accepted for login and recovery
// keys.
const MinRSABits = 3072

// algoDSA is named here only to refuse it with ACCESS_KEY_WEAK.
const algoDSA = "ssh-dss"

// Key is a parsed OpenSSH public key.
type Key struct {
	Fingerprint string `json:"fingerprint"`
	Type        string `json:"type"`
	PublicKey   string `json:"publicKey"`
	Comment     string `json:"comment,omitempty"`
}

// ParseLoginKey parses one authorized_keys line and applies the login key
// rules: ed25519, ECDSA P-256 and P-384, the FIDO forms of ed25519 and P-256,
// and RSA of at least 3072 bits.
func ParseLoginKey(line string) (Key, error) {
	pk, comment, err := parse(line)
	if err != nil {
		return Key{}, err
	}
	switch pk.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
	case ssh.KeyAlgoRSA:
		if err := checkRSA(pk); err != nil {
			return Key{}, err
		}
	case algoDSA:
		return Key{}, codes.New(codes.AccessKeyWeak, "DSA keys aren't accepted")
	default:
		return Key{}, codes.New(codes.AccessKeyType, "%s keys aren't accepted", pk.Type())
	}
	return keyOf(pk, comment), nil
}

// ParseRecoveryKey parses a recovery key: ed25519 or RSA of at least 3072
// bits. FIDO keys can sign but not decrypt, so a backup encrypted to one
// could never be opened; they are refused.
func ParseRecoveryKey(line string) (Key, error) {
	pk, comment, err := parse(line)
	if err != nil {
		return Key{}, err
	}
	switch pk.Type() {
	case ssh.KeyAlgoED25519:
	case ssh.KeyAlgoRSA:
		if err := checkRSA(pk); err != nil {
			return Key{}, err
		}
	case algoDSA:
		return Key{}, codes.New(codes.AccessKeyWeak, "DSA keys aren't accepted")
	default:
		return Key{}, codes.New(codes.AccessKeyType, "a recovery key must be ssh-ed25519 or ssh-rsa, not %s", pk.Type())
	}
	return keyOf(pk, comment), nil
}

func parse(line string) (ssh.PublicKey, string, error) {
	pk, comment, _, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, "", codes.New(codes.AccessKeyType, "the key isn't an OpenSSH public key")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, "", codes.New(codes.AccessKeyType, "give one key per line")
	}
	return pk, comment, nil
}

func checkRSA(pk ssh.PublicKey) error {
	cpk, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return codes.New(codes.AccessKeyType, "the RSA key can't be read")
	}
	rk, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		return codes.New(codes.AccessKeyType, "the RSA key can't be read")
	}
	if rk.N.BitLen() < MinRSABits {
		return codes.New(codes.AccessKeyWeak, "RSA keys need at least %d bits; this one has %d", MinRSABits, rk.N.BitLen())
	}
	return nil
}

func keyOf(pk ssh.PublicKey, comment string) Key {
	return Key{
		Fingerprint: ssh.FingerprintSHA256(pk),
		Type:        pk.Type(),
		PublicKey:   string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(pk))),
		Comment:     comment,
	}
}
