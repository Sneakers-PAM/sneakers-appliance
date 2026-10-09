// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package product_test

import (
	"os"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/product"
)

func TestUnstageDropsTheStagedSlotAndKeepsTheInstalledOne(t *testing.T) {
	e := newEnv(t, nil)
	if _, err := e.slots.Unstage(); !codes.Is(err, codes.UpgradeNotStaged) {
		t.Fatalf("nothing staged: want UPGRADE_NOT_STAGED, got %v", err)
	}
	e.stage(t, "0.2.0")
	if _, err := e.slots.Apply(); err != nil {
		t.Fatal(err)
	}
	current := e.slots.Current()
	e.stage(t, "0.3.0")
	staged := e.slots.Status()
	if staged.Staged != "0.3.0" {
		t.Fatalf("%+v", staged)
	}
	v, err := e.slots.Unstage()
	if err != nil || v != "0.3.0" {
		t.Fatalf("unstage %q %v", v, err)
	}
	if st := e.slots.Status(); st != (product.Status{Installed: "0.2.0"}) {
		t.Fatalf("after unstaging %+v", st)
	}
	if e.slots.Current() != current {
		t.Fatal("unstaging moved the running slot")
	}
	entries, _ := os.ReadDir(e.slots.Dir)
	for _, d := range entries {
		if d.Name() != "current" && d.Name() != "a" && d.Name() != "b" {
			t.Errorf("left behind: %s", d.Name())
		}
	}
	if _, err := os.Stat(current); err != nil {
		t.Fatal(err)
	}
}

func TestTheInstalledHeaderIsRead(t *testing.T) {
	e := newEnv(t, nil)
	if _, ok := e.slots.Installed(); ok {
		t.Fatal("a new box has no installed header")
	}
	e.stage(t, "0.2.0")
	if _, err := e.slots.Apply(); err != nil {
		t.Fatal(err)
	}
	h, ok := e.slots.Installed()
	if !ok || h.Version != "0.2.0" || len(h.Bases) != 1 {
		t.Fatalf("installed %+v %v", h, ok)
	}
}
