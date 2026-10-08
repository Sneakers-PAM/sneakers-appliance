// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP is HMAC-SHA-1, what every authenticator app reads
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// The TOTP parameters (RFC 6238): SHA-1, 6 digits, 30-second steps, and
// one step of drift either way.
const (
	Digits     = 6
	Period     = 30 * time.Second
	Algorithm  = "SHA1"
	secretSize = 20
	drift      = 1
)

// NewTOTPSecret returns a fresh 160-bit secret.
func NewTOTPSecret() ([]byte, error) {
	b := make([]byte, secretSize)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}
	return b, nil
}

// Base32 is the secret as an authenticator app takes it typed in.
func Base32(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// URI is the otpauth:// URI for the QR code.
func URI(secret []byte, issuer, account string) string {
	q := url.Values{}
	q.Set("secret", Base32(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", Algorithm)
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(int(Period.Seconds())))
	return "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(account) + "?" + q.Encode()
}

// Step is the 30-second step t falls in.
func Step(t time.Time) uint64 { return uint64(max(t.Unix(), 0)) / uint64(Period.Seconds()) } // #nosec G115 -- clamped

// TOTP is the code for t.
func TOTP(secret []byte, t time.Time) string { return hotp(secret, Step(t)) }

func hotp(secret []byte, counter uint64) string {
	m := hmac.New(sha1.New, secret)
	_ = binary.Write(m, binary.BigEndian, counter)
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

// VerifyTOTP checks code against the steps around now, newer than
// lastStep (the last step this admin used): a code is never taken twice.
// It returns the step the code matched.
func VerifyTOTP(secret []byte, code string, now time.Time, lastStep uint64) (uint64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return 0, false
	}
	cur := Step(now)
	matched, ok := uint64(0), false
	for d := -drift; d <= drift; d++ {
		s := cur + uint64(d) // #nosec G115 -- cur is far above drift
		if s <= lastStep {
			continue
		}
		if hmac.Equal([]byte(hotp(secret, s)), []byte(code)) {
			matched, ok = s, true
		}
	}
	return matched, ok
}

// sealKey is the AES-256 key the TOTP secrets are sealed with, derived from
// the pepper.
func sealKey(pepper []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, pepper, nil, "sneakers-appliance totp secrets v1", 32)
}

// SealTOTP seals admin's secret: AES-256-GCM under a key derived from the
// pepper, with the admin's name as associated data, so a sealed secret
// can't be moved to another admin.
func SealTOTP(pepper []byte, admin string, secret []byte) (string, error) {
	g, err := gcm(pepper)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("credentials: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(g.Seal(nonce, nonce, secret, []byte(admin))), nil
}

// OpenTOTP opens a sealed secret of admin's.
func OpenTOTP(pepper []byte, admin, sealed string) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(sealed)
	if err != nil {
		return nil, fmt.Errorf("credentials: the sealed TOTP secret doesn't decode: %w", err)
	}
	g, err := gcm(pepper)
	if err != nil {
		return nil, err
	}
	if len(b) < g.NonceSize() {
		return nil, errors.New("credentials: the sealed TOTP secret is too short")
	}
	out, err := g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], []byte(admin))
	if err != nil {
		return nil, fmt.Errorf("credentials: the TOTP secret doesn't open: %w", err)
	}
	return out, nil
}

func gcm(pepper []byte) (cipher.AEAD, error) {
	k, err := sealKey(pepper)
	if err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}
	return cipher.NewGCM(blk)
}
