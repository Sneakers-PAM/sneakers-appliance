// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package onetime_test

import (
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/onetime"
)

// dropped is every character a code never holds, because it reads like
// another one on a console.
const dropped = "01GILOQU"

func TestTheAlphabetIsTwentyEightCharactersWithNoLookAlikes(t *testing.T) {
	if onetime.Alphabet != "23456789ABCDEFHJKMNPRSTVWXYZ" {
		t.Fatalf("the alphabet is %q", onetime.Alphabet)
	}
	seen := map[rune]bool{}
	for _, r := range onetime.Alphabet {
		if seen[r] {
			t.Fatalf("%q is in the alphabet twice", r)
		}
		seen[r] = true
	}
	if len(seen) != 28 {
		t.Fatalf("the alphabet has %d characters", len(seen))
	}
	if strings.ContainsAny(onetime.Alphabet, dropped) {
		t.Fatalf("the alphabet %q has a look-alike", onetime.Alphabet)
	}
}

func TestNewCodesAreTwoGroupsOfFour(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c := onetime.New(8)
		if len(c) != 9 || c[4] != '-' {
			t.Fatalf("code %q isn't XXXX-XXXX", c)
		}
		seen[c] = true
	}
	if len(seen) < 195 {
		t.Fatalf("only %d distinct codes in 200", len(seen))
	}
	if c := onetime.New(16); len(c) != 19 || strings.Count(c, "-") != 3 {
		t.Fatalf("a 16-character code %q isn't four groups", c)
	}
	if c := onetime.New(4); len(c) != 4 {
		t.Fatalf("a 4-character code %q has a dash", c)
	}
}

func TestNewCodesHoldOnlyTheAlphabet(t *testing.T) {
	for range 20000 {
		for _, r := range strings.ReplaceAll(onetime.New(16), "-", "") {
			if !strings.ContainsRune(onetime.Alphabet, r) {
				t.Fatalf("%q isn't in the alphabet", r)
			}
		}
	}
}

// A modulo over bytes would make the first four characters about 11% more
// likely than the rest (256 = 9*28 + 4). At 100000 expected counts one
// standard deviation is about 316, so 2000 is far past chance but well
// inside that bias.
func TestNewCodesAreUniform(t *testing.T) {
	counts := map[rune]int{}
	for range 700000 {
		for _, r := range onetime.New(4) {
			counts[r]++
		}
	}
	for _, r := range onetime.Alphabet {
		if got := counts[r]; got < 98000 || got > 102000 {
			t.Errorf("%q came up %d times in 2800000; want about 100000", r, got)
		}
	}
}

func TestNewCodesReadBackThroughNormalize(t *testing.T) {
	for range 500 {
		c := onetime.New(16)
		for _, typed := range []string{c, strings.ToLower(c), strings.ReplaceAll(c, "-", " "), strings.ReplaceAll(c, "-", "")} {
			if got, ok := onetime.Normalize(typed, 16); !ok || got != c {
				t.Fatalf("Normalize(%q) = %q, %v; want %q", typed, got, ok, c)
			}
			if got, ok := onetime.NormalizeOld(typed, 16); !ok || got != c {
				t.Fatalf("NormalizeOld(%q) = %q, %v; want %q", typed, got, ok, c)
			}
		}
	}
}

func TestNormalizeForgivesCaseDashesAndSpaces(t *testing.T) {
	for in, want := range map[string]string{
		"7pxk-nms9":   "7PXK-NMS9",
		" 7PXK NMS9 ": "7PXK-NMS9",
		"7pxknms9":    "7PXK-NMS9",
	} {
		got, ok := onetime.Normalize(in, 8)
		if !ok || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "7PXK-NMS", "7PXK-NMS9X", "7PXK_NMS9!"} {
		if _, ok := onetime.Normalize(bad, 8); ok {
			t.Errorf("Normalize(%q) accepted", bad)
		}
	}
}

func TestNormalizeRefusesEveryDroppedCharacter(t *testing.T) {
	for _, r := range dropped + strings.ToLower(dropped) {
		typed := "7PXK-NMS" + string(r)
		if got, ok := onetime.Normalize(typed, 8); ok {
			t.Errorf("Normalize(%q) = %q; want it refused", typed, got)
		}
	}
}

// A code issued before the letters were dropped can still be live after an
// update: NormalizeOld reads it as it was read then.
func TestNormalizeOldReadsAnEarlierCode(t *testing.T) {
	for in, want := range map[string]string{
		"7PQK-NG09":   "7PQK-NG09",
		"7pqk-ng09":   "7PQK-NG09",
		"O1IL-ABCD":   "0111-ABCD",
		" GQ01 2345 ": "GQ01-2345",
	} {
		got, ok := onetime.NormalizeOld(in, 8)
		if !ok || got != want {
			t.Errorf("NormalizeOld(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "7PQK-NMS", "7PQK-NMS9X", "7PQK-NMSU", "7PQK_NMS9!"} {
		if _, ok := onetime.NormalizeOld(bad, 8); ok {
			t.Errorf("NormalizeOld(%q) accepted", bad)
		}
	}
}

func TestEncodeTakesTwoBytesForEachCharacter(t *testing.T) {
	if got := onetime.Encode(make([]byte, 16), 8); got != "2222-2222" {
		t.Fatalf("got %q", got)
	}
	ff := make([]byte, 16)
	for i := range ff {
		ff[i] = 0xff
	}
	if got := onetime.Encode(ff, 8); got != "JJJJ-JJJJ" {
		t.Fatalf("got %q", got)
	}
	b := make([]byte, 32)
	b[15] = 27
	if got := onetime.Encode(b, 8); got != "2222-222Z" {
		t.Fatalf("got %q", got)
	}
	b[16] = 0xff
	if got := onetime.Encode(b, 8); got != "2222-222Z" {
		t.Fatalf("bytes past the first 16 changed the code: %q", got)
	}
}
