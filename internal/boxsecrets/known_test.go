// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxsecrets_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsecrets"
)

type knownSettings struct {
	values map[string]string
	err    error
}

func (s knownSettings) Values() (map[string]string, error) { return s.values, s.err }

// Known is every value the box holds for the product and the settings that
// are passwords; a host name or a port isn't a secret to mask.
func TestKnownListsTheBoxsSecretValues(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, boxsecrets.ValuesFile), []byte(`{"a/b/c":"made-on-the-box"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st := &boxsecrets.Store{Dir: dir, Settings: knownSettings{values: map[string]string{"email.password": "relay-password", "email.host": "mail.example.org"}}}
	got, err := st.Known()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got, "made-on-the-box") || !slices.Contains(got, "relay-password") || slices.Contains(got, "mail.example.org") {
		t.Fatalf("known %v", got)
	}
}

func TestKnownWithNothingMadeYet(t *testing.T) {
	got, err := (&boxsecrets.Store{Dir: t.TempDir()}).Known()
	if err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
}

// Settings that don't read still leave the made values: the bundle masks
// what it can.
func TestKnownKeepsTheValuesWhenTheSettingsFail(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, boxsecrets.ValuesFile), []byte(`{"k":"made-on-the-box"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st := &boxsecrets.Store{Dir: dir, Settings: knownSettings{err: errors.New("no settings")}}
	got, err := st.Known()
	if err == nil || !slices.Contains(got, "made-on-the-box") {
		t.Fatalf("%v %v", got, err)
	}
}
