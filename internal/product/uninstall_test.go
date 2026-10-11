// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package product_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productinfo"
)

func (e env) install(t *testing.T, v string) {
	t.Helper()
	e.stage(t, v)
	if _, err := e.slots.Apply(); err != nil {
		t.Fatal(err)
	}
}

// After an uninstall the box has no product, and the bundle it ran is
// the staged one, so an apply installs it again from the same slot.
func TestUninstallKeepsTheInstalledBundleAsTheStagedOne(t *testing.T) {
	e := newEnv(t, nil)
	e.install(t, "0.2.0")
	slot := e.slots.Current()
	kept, removed, err := e.slots.Uninstall()
	if err != nil {
		t.Fatal(err)
	}
	if kept != "0.2.0" || removed != 0 {
		t.Fatalf("kept %q, removed %d bytes", kept, removed)
	}
	if st := e.slots.Status(); st.Installed != "" || st.Staged != "0.2.0" || st.Previous != "" {
		t.Fatalf("status %+v", st)
	}
	if productinfo.Installed(e.slots.Dir).Present() {
		t.Fatal("the shell still sees an installed product")
	}
	if _, err := os.Stat(filepath.Join(slot, "k0s")); err != nil {
		t.Fatalf("the kept slot lost its files: %v", err)
	}
	if v, err := e.slots.Apply(); err != nil || v != "0.2.0" || e.slots.Current() != slot {
		t.Fatalf("apply after the uninstall: %q, %v, current %s", v, err, e.slots.Current())
	}
}

// The previous slot and a staged update go: only the installed bundle is
// kept.
func TestUninstallDropsThePreviousAndTheStagedSlots(t *testing.T) {
	e := newEnv(t, nil)
	e.install(t, "0.2.0")
	e.install(t, "0.3.0")
	cur := e.slots.Current()
	kept, removed, err := e.slots.Uninstall()
	if err != nil {
		t.Fatal(err)
	}
	if kept != "0.3.0" || removed == 0 {
		t.Fatalf("kept %q, removed %d bytes", kept, removed)
	}
	if st := e.slots.Status(); st.Installed != "" || st.Staged != "0.3.0" || st.Previous != "" {
		t.Fatalf("status %+v", st)
	}
	ents, err := os.ReadDir(e.slots.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ents {
		if p := filepath.Join(e.slots.Dir, d.Name()); d.IsDir() && p != cur {
			t.Fatalf("slot %s is still there", d.Name())
		}
	}

	e = newEnv(t, nil)
	e.install(t, "0.2.0")
	e.stage(t, "0.3.0")
	if kept, _, err := e.slots.Uninstall(); err != nil || kept != "0.2.0" {
		t.Fatalf("kept %q, %v", kept, err)
	}
	if st := e.slots.Status(); st.Installed != "" || st.Staged != "0.2.0" || st.Previous != "" {
		t.Fatalf("status %+v", st)
	}
}

func TestUninstallWithNoProductIsRefused(t *testing.T) {
	e := newEnv(t, nil)
	if _, _, err := e.slots.Uninstall(); !codes.Is(err, codes.ProductNotInstalled) {
		t.Fatalf("want PRODUCT_NOT_INSTALLED, got %v", err)
	}
	e.stage(t, "0.2.0")
	if _, _, err := e.slots.Uninstall(); !codes.Is(err, codes.ProductNotInstalled) {
		t.Fatalf("a staged bundle alone: want PRODUCT_NOT_INSTALLED, got %v", err)
	}
}
