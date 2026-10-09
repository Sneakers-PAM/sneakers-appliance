// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productinfo_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productinfo"
)

// slotWith makes a product directory whose current slot holds header.
func slotWith(t *testing.T, header string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", productinfo.BundleFile), []byte(header), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(dir, "current")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestTheInstalledProductIsNamedFromItsHeader(t *testing.T) {
	dir := slotWith(t, `{"format":1,"name":"sneakers-product","version":"0.2.0","kind":"product"}`)
	got := productinfo.Installed(dir)
	want := productinfo.Info{Name: "sneakers", Title: "Sneakers", Version: "0.2.0"}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if !got.Present() {
		t.Fatal("an installed product isn't present")
	}
}

func TestNoProductBeforeTheFirstInstall(t *testing.T) {
	for name, dir := range map[string]string{
		"no directory":    filepath.Join(t.TempDir(), "missing"),
		"no current slot": t.TempDir(),
	} {
		if got := productinfo.Installed(dir); got.Present() || got != (productinfo.Info{}) {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

// A header that isn't a product's, or whose name can't be a command word,
// names no product, so nothing is offered for it.
func TestAHeaderThatNamesNoProductIsIgnored(t *testing.T) {
	for _, header := range []string{
		`not json`,
		`{"name":"sneakers-appliance","version":"0.2.0"}`,
		`{"name":"-product","version":"0.2.0"}`,
		`{"name":"Sneakers Two-product","version":"0.2.0"}`,
		`{"name":"status;id-product","version":"0.2.0"}`,
		`{"name":"sneakers-product","version":""}`,
	} {
		if got := productinfo.Installed(slotWith(t, header)); got.Present() {
			t.Errorf("%s: %+v", header, got)
		}
	}
}
