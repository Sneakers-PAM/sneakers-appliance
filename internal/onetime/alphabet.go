// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package onetime is the box's one-time codes: the console's setup code,
// an admin's invitation, the console's Recover access code, and the
// root-shell challenges and codes. Every code is drawn from Alphabet in
// groups of four, and read back case-insensitively with dashes and spaces
// ignored.
package onetime

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
)

// Alphabet is the 28 characters a code can hold. It leaves out every
// character that reads like another one on a console or in a web console's
// scaled font: 0, 1, G, I, L, O, Q and U. A character carries about 4.81
// bits, so 16 characters are about 76.9 bits and 8 about 38.5.
const Alphabet = "23456789ABCDEFHJKMNPRSTVWXYZ"

// oldAlphabet is what codes were drawn from before Alphabet. See
// NormalizeOld.
const oldAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// fairBytes is the largest multiple of len(Alphabet) a byte can reach: New
// throws away bytes at or above it, so no character comes up more than
// another.
const fairBytes = 256 - 256%len(Alphabet)

// New returns a random code of n characters, grouped in fours.
func New(n int) string {
	raw := make([]byte, 0, n)
	buf := make([]byte, n+8)
	for len(raw) < n {
		_, _ = rand.Read(buf)
		for _, v := range buf {
			if int(v) < fairBytes && len(raw) < n {
				raw = append(raw, Alphabet[int(v)%len(Alphabet)])
			}
		}
	}
	return group(raw)
}

// Encode turns the first 2n bytes of b into n characters, grouped in fours;
// b must hold at least that many. The same bytes must always give the same
// code, so it can't throw any away as New does; sixteen bits for a character
// leave a bias under 0.05%.
func Encode(b []byte, n int) string {
	raw := make([]byte, n)
	for i := range raw {
		raw[i] = Alphabet[int(binary.BigEndian.Uint16(b[2*i:]))%len(Alphabet)]
	}
	return group(raw)
}

func group(raw []byte) string {
	var out strings.Builder
	for i, c := range raw {
		if i > 0 && i%4 == 0 {
			out.WriteByte('-')
		}
		out.WriteByte(c)
	}
	return out.String()
}

// Normalize reads what an admin typed as an n-character code and returns
// it in its grouped form; ok is false when it can't be one.
func Normalize(s string, n int) (string, bool) {
	return read(s, n, func(r rune) (byte, bool) {
		if r < 128 && strings.ContainsRune(Alphabet, r) {
			return byte(r), true // #nosec G115 -- r is ASCII
		}
		return 0, false
	})
}

// NormalizeOld is Normalize for a code that can have been issued before
// Alphabet, which still reads G, Q, 0 and 1, with O read as 0 and I and L as
// 1. Every code from Alphabet reads the same here. It is only for the codes
// that outlive an update's reboot, the sealed setup and Recover access codes
// and an invitation, whose longest life is 24 hours.
func NormalizeOld(s string, n int) (string, bool) {
	return read(s, n, func(r rune) (byte, bool) {
		switch {
		case r == 'O':
			return '0', true
		case r == 'I' || r == 'L':
			return '1', true
		case r < 128 && strings.ContainsRune(oldAlphabet, r):
			return byte(r), true // #nosec G115 -- r is ASCII
		}
		return 0, false
	})
}

func read(s string, n int, char func(rune) (byte, bool)) (string, bool) {
	var raw []byte
	for _, r := range strings.ToUpper(s) {
		if r == '-' || r == ' ' || r == '\t' {
			continue
		}
		c, ok := char(r)
		if !ok {
			return "", false
		}
		raw = append(raw, c)
	}
	if len(raw) != n {
		return "", false
	}
	return group(raw), true
}
