// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package product_test

import (
	"os"
	"path/filepath"
	"testing"
)

// The installed version stages again, into the free slot, for a
// reinstall: an apply then runs it from a fresh copy, and the slot it
// replaced is the way back.
func TestTheInstalledVersionStagesAgainForAReinstall(t *testing.T) {
	e := newEnv(t, nil)
	e.install(t, "0.2.0")
	damaged := e.slots.Current()
	if err := os.Remove(filepath.Join(damaged, "k0s")); err != nil {
		t.Fatal(err)
	}
	e.stage(t, "0.2.0")
	if st := e.slots.Status(); st.Installed != "0.2.0" || st.Staged != "0.2.0" {
		t.Fatalf("status %+v", st)
	}
	v, err := e.slots.Apply()
	if err != nil || v != "0.2.0" {
		t.Fatalf("apply %q, %v", v, err)
	}
	if e.slots.Current() == damaged {
		t.Fatal("the reinstall runs from the slot it replaced")
	}
	if _, err := os.Stat(filepath.Join(e.slots.Current(), "k0s")); err != nil {
		t.Fatalf("the reinstalled slot: %v", err)
	}
	if st := e.slots.Status(); st.Previous != "0.2.0" {
		t.Fatalf("status %+v", st)
	}
	if _, err := e.slots.Revert(); err != nil || e.slots.Current() != damaged {
		t.Fatalf("revert: %v, current %s", err, e.slots.Current())
	}
}
