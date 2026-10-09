// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package product_test

import (
	"crypto/ecdsa"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/product"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

type env struct {
	slots product.Slots
	key   *ecdsa.PublicKey
	tree  fstest.MapFS
}

func newEnv(t *testing.T, edit func(fstest.MapFS)) env {
	t.Helper()
	k := fixtures.LabKeys(t)
	key, err := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	if err != nil {
		t.Fatal(err)
	}
	tree, _ := fixtures.ProductTree(t, k, "amd64", edit)
	return env{slots: product.Slots{Dir: filepath.Join(t.TempDir(), "product")}, key: key, tree: tree}
}

func header(v string) updatepkg.Header {
	return updatepkg.Header{Format: updatepkg.Format, Name: updatepkg.NameProduct, Version: v, Arch: "amd64", Kind: updatepkg.KindProduct, Bases: []string{"0.2.0"}, Channel: release.ChannelLab}
}

// fill writes the tree the way an unpack would: every file 0644.
func (e env) fill(dir string) error {
	for name, f := range e.tree {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, f.Data, 0o644); err != nil { // #nosec G306 -- test files
			return err
		}
	}
	return nil
}

func (e env) stage(t *testing.T, v string) {
	t.Helper()
	if err := e.slots.Stage(header(v), e.fill, e.key); err != nil {
		t.Fatal(err)
	}
}

func TestANewBoxHasNoProduct(t *testing.T) {
	e := newEnv(t, nil)
	if st := e.slots.Status(); st != (product.Status{}) {
		t.Fatalf("status %+v", st)
	}
	if _, err := e.slots.Apply(); !codes.Is(err, codes.UpgradeNotStaged) {
		t.Fatalf("apply: want UPGRADE_NOT_STAGED, got %v", err)
	}
	if _, err := e.slots.Revert(); !codes.Is(err, codes.UpgradeNoPrevious) {
		t.Fatalf("revert: want UPGRADE_NO_PREVIOUS, got %v", err)
	}
}

func TestTheFirstInstallIsAStageAndAnApplyWithNoPrevious(t *testing.T) {
	e := newEnv(t, nil)
	e.stage(t, "0.2.0")
	if st := e.slots.Status(); st.Staged != "0.2.0" || st.Installed != "" {
		t.Fatalf("staged status %+v", st)
	}
	if v, err := e.slots.Apply(); err != nil || v != "0.2.0" {
		t.Fatalf("apply %q, %v", v, err)
	}
	if st := e.slots.Status(); st != (product.Status{Installed: "0.2.0"}) {
		t.Fatalf("installed status %+v", st)
	}
	for _, bin := range []string{"k0s", "helm"} {
		fi, err := os.Stat(filepath.Join(e.slots.Current(), bin))
		if err != nil || fi.Mode().Perm() != 0o755 {
			t.Fatalf("%s in the current slot: %v %v", bin, fi, err)
		}
	}
	if _, err := os.Stat(filepath.Join(e.slots.Current(), product.BundleFile)); err != nil {
		t.Fatal(err)
	}
}

func TestAnUpgradeKeepsThePreviousSlotAsTheWayBack(t *testing.T) {
	e := newEnv(t, nil)
	e.stage(t, "0.2.0")
	if _, err := e.slots.Apply(); err != nil {
		t.Fatal(err)
	}
	first := e.slots.Current()
	e.stage(t, "0.3.0")
	if _, err := e.slots.Apply(); err != nil {
		t.Fatal(err)
	}
	if st := e.slots.Status(); st.Installed != "0.3.0" || st.Previous != "0.2.0" {
		t.Fatalf("after the upgrade %+v", st)
	}
	if e.slots.Current() == first {
		t.Fatal("the upgrade went into the running slot")
	}
	if v, err := e.slots.Revert(); err != nil || v != "0.2.0" {
		t.Fatalf("revert %q, %v", v, err)
	}
	if st := e.slots.Status(); st.Installed != "0.2.0" || e.slots.Current() != first {
		t.Fatalf("after the revert %+v", st)
	}
}

func TestOnlyANewerVersionStages(t *testing.T) {
	e := newEnv(t, nil)
	e.stage(t, "0.3.0")
	if _, err := e.slots.Apply(); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"0.3.0", "0.2.0"} {
		if err := e.slots.Stage(header(v), e.fill, e.key); !codes.Is(err, codes.UpgradeDowngrade) {
			t.Fatalf("%s: want UPGRADE_DOWNGRADE, got %v", v, err)
		}
	}
}

func TestABundleThatDoesntCheckOutIsNeverStaged(t *testing.T) {
	e := newEnv(t, fixtures.SwapK0sBinary)
	if err := e.slots.Stage(header("0.2.0"), e.fill, e.key); !codes.Is(err, codes.KitBundleMismatch) {
		t.Fatalf("want KIT_BUNDLE_MISMATCH, got %v", err)
	}
	if st := e.slots.Status(); st != (product.Status{}) {
		t.Fatalf("status %+v", st)
	}
	e2 := newEnv(t, nil)
	boom := errors.New("the unpack failed")
	if err := e2.slots.Stage(header("0.2.0"), func(string) error { return boom }, e2.key); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if st := e2.slots.Status(); st.Staged != "" {
		t.Fatalf("status %+v", st)
	}
}

func TestStagingTwiceReplacesTheStagedSlotNotTheRunningOne(t *testing.T) {
	e := newEnv(t, nil)
	e.stage(t, "0.2.0")
	if _, err := e.slots.Apply(); err != nil {
		t.Fatal(err)
	}
	cur := e.slots.Current()
	e.stage(t, "0.3.0")
	e.stage(t, "0.4.0")
	if st := e.slots.Status(); st.Staged != "0.4.0" || st.Installed != "0.2.0" || st.Previous != "" || e.slots.Current() != cur {
		t.Fatalf("status %+v", st)
	}
}
