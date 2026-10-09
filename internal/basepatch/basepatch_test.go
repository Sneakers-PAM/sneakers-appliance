// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package basepatch_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/basepatch"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

func noise(n int, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

// edit is base with a few bytes changed and some appended: a new release
// that shares almost everything with the old one.
func edit(base []byte) []byte {
	t := bytes.Clone(base)
	copy(t[len(t)/3:], "a version stamp that moved")
	return append(t, []byte("one more file")...)
}

func sumOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestADeltaRebuildsTheTargetExactly(t *testing.T) {
	base := noise(1<<20, 1)
	target := edit(base)
	var d bytes.Buffer
	if err := basepatch.MakeDelta(base, target, &d); err != nil {
		t.Fatal(err)
	}
	if d.Len() > 64<<10 {
		t.Fatalf("a small change gave a %d byte delta", d.Len())
	}
	if err := basepatch.Check(bytes.NewReader(d.Bytes()), base, target); err != nil {
		t.Fatal(err)
	}
	if err := basepatch.Check(bytes.NewReader(d.Bytes()), noise(1<<20, 2), target); err == nil {
		t.Fatal("a delta rebuilt the target from another base")
	}
}

// The release build makes its deltas with the zstd command; the box's
// decoder reads them.
func TestTheZstdCommandsDeltaRebuilds(t *testing.T) {
	zstdBin, err := exec.LookPath("zstd")
	if err != nil {
		t.Skip("no zstd command here")
	}
	dir := t.TempDir()
	base := noise(4<<20, 3)
	target := edit(base)
	for name, b := range map[string][]byte{"base": base, "target": target} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(zstdBin, "-q", "-19", "--long=30", "--patch-from="+filepath.Join(dir, "base"), filepath.Join(dir, "target"), "-o", filepath.Join(dir, "delta")) // #nosec G204 -- test-only
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zstd: %v %s", err, out)
	}
	d, err := os.ReadFile(filepath.Join(dir, "delta"))
	if err != nil {
		t.Fatal(err)
	}
	if err := basepatch.Check(bytes.NewReader(d), base, target); err != nil {
		t.Fatal(err)
	}
}

func spec(baseRoot, baseUKI, root, uki []byte) basepatch.Spec {
	return basepatch.Spec{BaseVersion: "0.3.0", BaseRootSHA256: sumOf(baseRoot), BaseRootSize: int64(len(baseRoot)), BaseUKISHA256: sumOf(baseUKI),
		RootSHA256: sumOf(root), UKISHA256: sumOf(uki)}
}

// The base is the first root_size bytes of the slot (the rest of the slot
// is whatever was there) and the running UKI; anything else is refused
// before a byte is written.
func TestTheBaseIsCheckedFirst(t *testing.T) {
	root, uki := noise(64<<10, 4), noise(8<<10, 5)
	s := spec(root, uki, edit(root), edit(uki))
	slot := append(bytes.Clone(root), noise(4096, 6)...)
	got, err := basepatch.ReadBase(s, "0.3.0", bytes.NewReader(slot), uki)
	if err != nil || !bytes.Equal(got, root) {
		t.Fatalf("the base: %v", err)
	}
	for name, run := range map[string]func() error{
		"another running version": func() error { _, err := basepatch.ReadBase(s, "0.2.9", bytes.NewReader(slot), uki); return err },
		"another UKI":             func() error { _, err := basepatch.ReadBase(s, "0.3.0", bytes.NewReader(slot), edit(uki)); return err },
		"another root image":      func() error { _, err := basepatch.ReadBase(s, "0.3.0", bytes.NewReader(edit(root)), uki); return err },
		"a short slot":            func() error { _, err := basepatch.ReadBase(s, "0.3.0", bytes.NewReader(root[:100]), uki); return err },
	} {
		if err := run(); !codes.Is(err, codes.UpgradePatchBase) {
			t.Errorf("%s: want UPGRADE_PATCH_BASE, got %v", name, err)
		}
	}
}

func layoutWithDeltas(t *testing.T, baseRoot, baseUKI, root, uki []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, basepatch.Dir), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		name         string
		base, target []byte
	}{{basepatch.RootDelta, baseRoot, root}, {basepatch.UKIDelta, baseUKI, uki}} {
		var d bytes.Buffer
		if err := basepatch.MakeDelta(f.base, f.target, &d); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f.name), d.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRebuildWritesBothBlobsAndDropsTheDeltas(t *testing.T) {
	baseRoot, baseUKI := noise(256<<10, 7), noise(16<<10, 8)
	root, uki := edit(baseRoot), edit(baseUKI)
	dir := layoutWithDeltas(t, baseRoot, baseUKI, root, uki)
	if err := basepatch.Rebuild(dir, spec(baseRoot, baseUKI, root, uki), baseRoot, baseUKI); err != nil {
		t.Fatal(err)
	}
	for _, want := range [][]byte{root, uki} {
		got, err := os.ReadFile(filepath.Join(dir, "blobs", "sha256", sumOf(want))) // #nosec G304 -- test-only
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("blob %s: %v", sumOf(want)[:12], err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, basepatch.Dir)); !os.IsNotExist(err) {
		t.Fatalf("the deltas are left: %v", err)
	}
}

// A delta that rebuilds other bytes than the signed header names is
// refused, and leaves no blob behind.
func TestARebuildThatIsntTheTargetIsRefused(t *testing.T) {
	baseRoot, baseUKI := noise(64<<10, 9), noise(8<<10, 10)
	root, uki := edit(baseRoot), edit(baseUKI)
	dir := layoutWithDeltas(t, baseRoot, baseUKI, root, uki)
	s := spec(baseRoot, baseUKI, root, uki)
	s.RootSHA256 = sumOf([]byte("something else"))
	err := basepatch.Rebuild(dir, s, baseRoot, baseUKI)
	if !codes.Is(err, codes.UpgradePatchResult) {
		t.Fatalf("want UPGRADE_PATCH_RESULT, got %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "blobs", "sha256", "*")); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	if err := os.Remove(filepath.Join(dir, basepatch.UKIDelta)); err != nil {
		t.Fatal(err)
	}
	if err := basepatch.Rebuild(dir, spec(baseRoot, baseUKI, root, uki), baseRoot, baseUKI); !codes.Is(err, codes.UpgradePatchResult) {
		t.Fatalf("a missing delta: %v", err)
	}
}
