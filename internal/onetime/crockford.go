// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package onetime is the box's one-time codes: the console's setup code,
// an admin's invitation, the console's Recover access code, and the
// root-shell challenges and codes. Every code is Crockford base32 in
// groups of four, read back case-insensitively with dashes and spaces
// ignored, and with O read as 0 and I and L as 1.
package onetime

import (
	"crypto/rand"
	"strings"
)

// alphabet is Crockford's base32: no I, L, O or U.
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// New returns a random code of n characters (a multiple of 4), grouped.
func New(n int) string {
	b := make([]byte, (n*5+7)/8)
	_, _ = rand.Read(b)
	return Encode(b, n)
}

// Encode turns the first n*5 bits of b into n characters, grouped in fours.
func Encode(b []byte, n int) string {
	var out strings.Builder
	for i := range n {
		if i > 0 && i%4 == 0 {
			out.WriteByte('-')
		}
		out.WriteByte(alphabet[bits5(b, i*5)])
	}
	return out.String()
}

func bits5(b []byte, off int) int {
	v := 0
	for j := range 5 {
		bit := off + j
		v <<= 1
		if bit/8 < len(b) && b[bit/8]&(0x80>>(bit%8)) != 0 {
			v |= 1
		}
	}
	return v
}

// Normalize reads what an admin typed as an n-character code and returns
// it in its grouped form; ok is false when it can't be one.
func Normalize(s string, n int) (string, bool) {
	var raw []byte
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == '-' || r == ' ' || r == '\t':
			continue
		case r == 'O':
			raw = append(raw, '0')
		case r == 'I' || r == 'L':
			raw = append(raw, '1')
		case r < 128 && strings.IndexByte(alphabet, byte(r)) >= 0:
			raw = append(raw, byte(r))
		default:
			return "", false
		}
	}
	if len(raw) != n {
		return "", false
	}
	var out strings.Builder
	for i, c := range raw {
		if i > 0 && i%4 == 0 {
			out.WriteByte('-')
		}
		out.WriteByte(c)
	}
	return out.String(), true
}
