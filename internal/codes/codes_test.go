// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package codes_test

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

func TestRegistryAcceptsEveryEntry(t *testing.T) {
	if _, err := codes.Registry(); err != nil {
		t.Fatal(err)
	}
}

func TestIsWalksTheChain(t *testing.T) {
	err := fmt.Errorf("build: %w", codes.New(codes.KitChannel, "the manifest is lab"))
	if !codes.Is(err, codes.KitChannel) || codes.Is(err, codes.KitPinMissing) {
		t.Fatal("Is")
	}
	if codes.Is(errors.New("plain"), codes.KitChannel) {
		t.Fatal("plain error carries no code")
	}
}

func TestDescribe(t *testing.T) {
	got := codes.Describe(codes.New(codes.KitChannel, "the manifest's channel is lab; this kit is production"))
	want := "KIT_CHANNEL (1004): the manifest's channel is lab; this kit is production"
	if got != want {
		t.Fatalf("got %q", got)
	}
}

func TestEveryCodeIsDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../docs/kit.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range codes.Entries {
		row := fmt.Sprintf("| %d | `%s` |", e.Code, e.Symbol)
		if !strings.Contains(string(doc), row) {
			t.Errorf("docs/kit.md has no row for %s", row)
		}
	}
}
