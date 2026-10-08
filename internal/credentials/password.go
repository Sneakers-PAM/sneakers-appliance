// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package credentials is how the box keeps an admin's password and TOTP
// secret (spec 2, Section 2.6): argon2id over the password keyed with the
// box's sealed pepper, the NIST SP 800-63B password rules with a
// breached-password list, RFC 6238 TOTP, and the TOTP secrets sealed with
// a key derived from the pepper.
package credentials

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// MinPasswordLength is the shortest password, in characters.
const MinPasswordLength = 12

// The argon2id parameters: 64 MiB, 3 passes, 4 lanes, a 32-byte hash.
const (
	argonMemory  = 64 * 1024
	argonTime    = 3
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// MaxPasswordBytes bounds what is hashed, so a huge paste can't tie up the
// box.
const MaxPasswordBytes = 1024

// HashPassword returns the stored form of password:
// $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>, over HMAC-SHA-256(pepper,
// password).
func HashPassword(pepper []byte, password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("credentials: %w", err)
	}
	sum := argon2.IDKey(keyed(pepper, password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(sum)), nil
}

// VerifyPassword reports whether password matches the stored hash.
func VerifyPassword(pepper []byte, stored, password string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || m > 1<<20 || t == 0 || t > 16 || p == 0 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := enc.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey(keyed(pepper, password), salt, t, m, p, uint32(len(want))) // #nosec G115 -- a 32-byte hash
	return subtle.ConstantTimeCompare(got, want) == 1
}

func keyed(pepper []byte, password string) []byte {
	if len(password) > MaxPasswordBytes {
		password = password[:MaxPasswordBytes]
	}
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte(password))
	return m.Sum(nil)
}

// CheckPassword applies the password rules: at least 12 characters, not
// the admin's name, not on the breached-password list. There are no
// composition rules.
func CheckPassword(password, admin string) error {
	if n := utf8.RuneCountInString(password); n < MinPasswordLength {
		return codes.New(codes.AccessPassword, "use at least %d characters; this one has %d", MinPasswordLength, n)
	}
	if len(password) > MaxPasswordBytes {
		return codes.New(codes.AccessPassword, "use at most %d bytes", MaxPasswordBytes)
	}
	if admin != "" && strings.EqualFold(password, admin) {
		return codes.New(codes.AccessPassword, "the password can't be the admin's name")
	}
	if Breached(password) {
		return codes.New(codes.AccessPassword, "this password is on a list of breached passwords; choose another")
	}
	return nil
}

//go:embed breached.bin
var breached []byte

const prefixSize = 6

// Breached reports whether password, in lower case, is on the breached
// list (build/tools/breached; scripts/breached-passwords.sh).
func Breached(password string) bool {
	sum := sha256.Sum256([]byte(strings.ToLower(password)))
	key := sum[:prefixSize]
	n := len(breached) / prefixSize
	i := sort.Search(n, func(i int) bool { return bytes.Compare(breached[i*prefixSize:(i+1)*prefixSize], key) >= 0 })
	return i < n && bytes.Equal(breached[i*prefixSize:(i+1)*prefixSize], key)
}

// BreachedCount is the list's length.
func BreachedCount() int { return len(breached) / prefixSize }
