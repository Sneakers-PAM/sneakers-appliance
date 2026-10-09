// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxname_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxname"
)

var shape = regexp.MustCompile(`^sneakers-[0-9a-f]{8}$`)

func TestTheNameIsMadeOnceAndKept(t *testing.T) {
	state := t.TempDir()
	first, err := boxname.Ensure(state)
	if err != nil {
		t.Fatal(err)
	}
	if !shape.MatchString(first) {
		t.Fatalf("name %q isn't sneakers-<8 hex>", first)
	}
	again, err := boxname.Ensure(state)
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Fatalf("the name changed from %q to %q", first, again)
	}
	b, err := os.ReadFile(boxname.Path(state))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != first+"\n" {
		t.Fatalf("file holds %q", b)
	}
}

func TestTwoBoxesGetDifferentNames(t *testing.T) {
	a, _ := boxname.Ensure(t.TempDir())
	b, _ := boxname.Ensure(t.TempDir())
	if a == b {
		t.Fatalf("both boxes are %q", a)
	}
}

func TestAnEarlierK0sNodeNameIsKept(t *testing.T) {
	state := t.TempDir()
	if err := os.MkdirAll(filepath.Join(state, "k0s"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "k0s", "node-name"), []byte("sneakers-0a1b2c3d\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := boxname.Ensure(state)
	if err != nil {
		t.Fatal(err)
	}
	if got != "sneakers-0a1b2c3d" {
		t.Fatalf("got %q, want the k0s node name", got)
	}
}

func TestADamagedFileIsReplaced(t *testing.T) {
	state := t.TempDir()
	if err := os.WriteFile(boxname.Path(state), []byte("not a name!\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := boxname.Ensure(state)
	if err != nil {
		t.Fatal(err)
	}
	if !shape.MatchString(got) {
		t.Fatalf("got %q", got)
	}
}
