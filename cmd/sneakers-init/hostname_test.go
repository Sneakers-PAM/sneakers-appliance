// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxname"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxvalues"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
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

// Init records the box's Base OS and Base Web versions at every boot,
// before k0s puts the product's stacks in place: the Base Web is the slot
// osadmin last served, else (built-in pages, or none recorded) the Base OS.
func TestBootRecordsTheBoxVersions(t *testing.T) {
	state := t.TempDir()
	if err := recordBoxVersions(state, "0.1.0-n"); err != nil {
		t.Fatal(err)
	}
	got := boxvalues.Read(filepath.Join(state, "platform"))
	if got[productspec.BoxOSVersion] != "0.1.0-n" || got[productspec.BoxWebVersion] != "0.1.0-n" {
		t.Fatalf("no served record: %v", got)
	}

	served := filepath.Join(osadmin.Paths{State: state}.OwnDir(), osadmin.WebServedFile)
	if err := os.MkdirAll(filepath.Dir(served), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ served, want string }{
		{`{"version":"0.1.0-m2","source":"slot","slot":"b"}`, "0.1.0-m2"},
		{`{"version":"0.1.0-m","source":"built-in"}`, "0.1.0-n"},
		{`not json`, "0.1.0-n"},
	} {
		if err := os.WriteFile(served, []byte(c.served), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := recordBoxVersions(state, "0.1.0-n"); err != nil {
			t.Fatal(err)
		}
		if got := boxvalues.Read(filepath.Join(state, "platform"))[productspec.BoxWebVersion]; got != c.want {
			t.Errorf("served %s: Base Web %q, want %q", c.served, got, c.want)
		}
	}
}
