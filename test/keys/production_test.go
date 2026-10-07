// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package keys checks that keys/production/ holds public material only.
package keys

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// privateMarkers are what a PEM, cosign or age private key carries.
var privateMarkers = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|ENCRYPTED SIGSTORE PRIVATE KEY|ENCRYPTED COSIGN PRIVATE KEY|"kdf"\s*:|AGE-SECRET-KEY-`)

func TestProductionKeysArePublic(t *testing.T) {
	checkPublic(t, "../../keys/production")
}

func checkPublic(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	}
	checkPublicWith(t, dir)
}

func TestTheCheckCatchesAPrivateKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "db.key"), []byte("-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inner := &recorder{}
	checkPublicWith(inner, dir)
	if !inner.failed {
		t.Fatal("a PEM private key wasn't caught")
	}
}

func TestTheCheckCatchesAnAgeIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "update.key"), []byte("# created: now\n"+"AGE-SECRET-"+"KEY-1"+strings.Repeat("Q", 58)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inner := &recorder{}
	checkPublicWith(inner, dir)
	if !inner.failed {
		t.Fatal("an age identity (the update key's private half) wasn't caught")
	}
}

type recorder struct{ failed bool }

func (r *recorder) Errorf(string, ...any) { r.failed = true }

func checkPublicWith(r interface{ Errorf(string, ...any) }, dir string) {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p) // #nosec G304 -- the test's own directory
		if privateMarkers.Match(b) {
			r.Errorf("%s holds a private key", p)
		}
		return nil
	})
}
