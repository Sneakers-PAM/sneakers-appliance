// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxname"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

func TestTheBootHostNameIsTheBoxNameWithNoSetting(t *testing.T) {
	state := t.TempDir()
	got, err := bootHostname(state)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^sneakers-[0-9a-f]{8}$`).MatchString(got) {
		t.Fatalf("host name %q", got)
	}
	own, _ := boxname.Ensure(state)
	if own != got {
		t.Fatalf("host name %q isn't the box's kept name %q", got, own)
	}
}

func TestTheBootHostNameIsTheSettingWhenThereIsOne(t *testing.T) {
	state := t.TempDir()
	s := network.Defaults("eth0")
	s.Hostname = "appliance.example.org"
	if err := os.MkdirAll(filepath.Join(state, "settings"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := network.WriteFile(filepath.Join(state, "settings", "network.yaml"), s); err != nil {
		t.Fatal(err)
	}
	got, err := bootHostname(state)
	if err != nil {
		t.Fatal(err)
	}
	if got != "appliance.example.org" {
		t.Fatalf("host name %q", got)
	}
	if _, err := os.Stat(boxname.Path(state)); err != nil {
		t.Fatalf("the box's own name wasn't made too: %v", err)
	}
}
