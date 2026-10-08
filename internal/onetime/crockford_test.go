// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package onetime_test

import (
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/onetime"
)

func TestNewCodesAreTwoGroupsOfFourCrockford(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c := onetime.New(8)
		if len(c) != 9 || c[4] != '-' {
			t.Fatalf("code %q isn't XXXX-XXXX", c)
		}
		if strings.ContainsAny(c, "ILOU") {
			t.Fatalf("code %q has a look-alike letter", c)
		}
		seen[c] = true
	}
	if len(seen) < 195 {
		t.Fatalf("only %d distinct codes in 200", len(seen))
	}
	if c := onetime.New(16); len(c) != 19 || strings.Count(c, "-") != 3 {
		t.Fatalf("a 16-character code %q isn't four groups", c)
	}
}

func TestNormalizeForgivesCaseDashesSpacesAndLookAlikes(t *testing.T) {
	for in, want := range map[string]string{
		"7pqk-nms9":   "7PQK-NMS9",
		" 7PQK NMS9 ": "7PQK-NMS9",
		"7pqknms9":    "7PQK-NMS9",
		"O1IL-ABCD":   "0111-ABCD",
	} {
		got, ok := onetime.Normalize(in, 8)
		if !ok || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "7PQK-NMS", "7PQK-NMS9X", "7PQK-NMSU", "7PQK_NMS9!"} {
		if _, ok := onetime.Normalize(bad, 8); ok {
			t.Errorf("Normalize(%q) accepted", bad)
		}
	}
}

func TestEncodeGroupsBytes(t *testing.T) {
	if got := onetime.Encode([]byte{0, 0, 0, 0, 0}, 8); got != "0000-0000" {
		t.Fatalf("got %q", got)
	}
	if got := onetime.Encode([]byte{0xff, 0xff, 0xff, 0xff, 0xff}, 8); got != "ZZZZ-ZZZZ" {
		t.Fatalf("got %q", got)
	}
}
