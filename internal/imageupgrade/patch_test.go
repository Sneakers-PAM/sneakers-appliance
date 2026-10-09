// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package imageupgrade_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/basepatch"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/imageupgrade"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
)

// activeSlots is fakeSlots whose running slot holds base, then whatever
// else the partition held.
type activeSlots struct {
	fakeSlots
	running []byte
}

func (s *activeSlots) OpenActive(context.Context) (io.ReaderAt, io.Closer, error) {
	return bytes.NewReader(append(bytes.Clone(s.running), make([]byte, 4096)...)), io.NopCloser(nil), nil
}

// baseOf is a made-up base release for the fixture artifact: its root
// image and UKI with a few bytes changed, as an earlier build would be.
func baseOf(t *testing.T, dir string) (root, uki []byte) {
	t.Helper()
	big, err := basepatch.BlobsOf(dir)
	if err != nil {
		t.Fatal(err)
	}
	read := func(hex string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, "blobs", "sha256", hex)) // #nosec G304 -- test-only
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	root, uki = read(big.Root.Digest.Encoded()), read(big.UKI.Digest.Encoded())
	root, uki = append([]byte("an older build "), root...), append([]byte("an older UKI "), uki...)
	return root, uki
}

// patchFor writes the fixture artifact as a patch payload against base:
// the layout less the two blobs, and their deltas.
func patchFor(t *testing.T, dir string, baseRoot, baseUKI []byte) (string, basepatch.Spec) {
	t.Helper()
	baseDir := t.TempDir()
	big, err := basepatch.BlobsOf(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The base "artifact" is the target's layout with the base's bytes in
	// the two blobs' places, enough for MakePayload to find them.
	if err := os.CopyFS(baseDir, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	for d, b := range map[string][]byte{big.Root.Digest.Encoded(): baseRoot, big.UKI.Digest.Encoded(): baseUKI} {
		if err := os.WriteFile(filepath.Join(baseDir, "blobs", "sha256", d), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out := t.TempDir()
	delta := func(base, target, delta string) error {
		b, _ := os.ReadFile(base)    // #nosec G304 -- test-only
		tg, _ := os.ReadFile(target) // #nosec G304 -- test-only
		f, err := os.Create(delta)   // #nosec G304 -- test-only
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		return basepatch.MakeDelta(b, tg, f)
	}
	pb, pt, err := basepatch.MakePayload(baseDir, dir, out, delta)
	if err != nil {
		t.Fatal(err)
	}
	// MakePayload hashed the base blobs as written, so the spec's base
	// hashes are those of baseRoot and baseUKI.
	return out, basepatch.Spec{BaseVersion: "0.0.9", BaseRootSHA256: pb.RootSHA256, BaseRootSize: pb.RootSize, BaseUKISHA256: pb.UKISHA256, RootSHA256: pt.RootSHA256, UKISHA256: pt.UKISHA256}
}

func patchStager(t *testing.T, runningRoot, runningUKI []byte) (*imageupgrade.Stager, string, *activeSlots) {
	t.Helper()
	s, dir, _, _, _ := stager(t, "0.0.9")
	esp := s.ESP.(orderESP).dir
	if err := os.WriteFile(filepath.Join(esp, imageupgrade.UKIDir, imageupgrade.GoodName("0.0.9")), runningUKI, 0o600); err != nil {
		t.Fatal(err)
	}
	slots := &activeSlots{running: runningRoot}
	s.Slots = slots
	return s, dir, slots
}

// Patch equals full: a patch rebuilt on the base the box runs stages the
// same release, writing the same root image, as the full layout does.
func TestAPatchStagesTheSameReleaseAsTheFullLayout(t *testing.T) {
	_, dir, _, _, _ := stager(t, "0.0.9")
	baseRoot, baseUKI := baseOf(t, dir)
	payload, spec := patchFor(t, dir, baseRoot, baseUKI)
	s, full, slots := patchStager(t, baseRoot, baseUKI)
	_ = full
	ver, err := s.StagePatch(ctx, payload, spec, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	big, _ := basepatch.BlobsOf(dir)
	if slots.written != big.Root.Size || slots.partUUID == "" || ver == "" {
		t.Fatalf("staged %s, slot %+v", ver, slots.fakeSlots)
	}
	if _, err := os.Stat(filepath.Join(payload, basepatch.Dir)); !os.IsNotExist(err) {
		t.Fatal("the deltas are left in the layout")
	}
	ref, _, _, _, _ := stager(t, "0.0.9")
	rv, err := ref.Stage(ctx, verify.LocalLayout(dir), "amd64")
	if err != nil || rv != ver {
		t.Fatalf("the full layout stages %s (%v); the patch %s", rv, err, ver)
	}
}

// A box whose running root or UKI isn't the patch's base refuses it before
// anything is written.
func TestAPatchOnAnotherBaseWritesNothing(t *testing.T) {
	_, dir, _, _, _ := stager(t, "0.0.9")
	baseRoot, baseUKI := baseOf(t, dir)
	payload, spec := patchFor(t, dir, baseRoot, baseUKI)
	for name, running := range map[string][2][]byte{
		"another root image": {append([]byte("x"), baseRoot...), baseUKI},
		"another UKI":        {baseRoot, append([]byte("x"), baseUKI...)},
	} {
		s, _, slots := patchStager(t, running[0], running[1])
		if _, err := s.StagePatch(ctx, payload, spec, "amd64"); !codes.Is(err, codes.UpgradePatchBase) {
			t.Errorf("%s: want UPGRADE_PATCH_BASE, got %v", name, err)
		}
		if slots.written != 0 {
			t.Errorf("%s: %d bytes written", name, slots.written)
		}
	}
	s, _, _ := patchStager(t, baseRoot, baseUKI)
	s.Running = "0.0.8"
	if _, err := s.StagePatch(ctx, payload, spec, "amd64"); !codes.Is(err, codes.UpgradePatchBase) {
		t.Fatalf("another running version: %v", err)
	}
}

// A patch whose rebuild isn't the target stages nothing.
func TestAPatchThatRebuildsOtherBytesStagesNothing(t *testing.T) {
	_, dir, _, _, _ := stager(t, "0.0.9")
	baseRoot, baseUKI := baseOf(t, dir)
	payload, spec := patchFor(t, dir, baseRoot, baseUKI)
	spec.UKISHA256 = spec.BaseUKISHA256
	s, _, slots := patchStager(t, baseRoot, baseUKI)
	if _, err := s.StagePatch(ctx, payload, spec, "amd64"); !codes.Is(err, codes.UpgradePatchResult) {
		t.Fatalf("want UPGRADE_PATCH_RESULT, got %v", err)
	}
	if slots.written != 0 {
		t.Fatalf("%d bytes written", slots.written)
	}
}

// A slot that can't read the running root can't apply a patch.
func TestWithoutTheRunningSlotAPatchIsRefused(t *testing.T) {
	s, dir, _, _, _ := stager(t, "0.0.9")
	if _, err := s.StagePatch(ctx, dir, basepatch.Spec{BaseVersion: "0.0.9"}, "amd64"); !codes.Is(err, codes.UpgradePatchBase) {
		t.Fatalf("got %v", err)
	}
}
