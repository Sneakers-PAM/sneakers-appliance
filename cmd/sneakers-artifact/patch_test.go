// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/basepatch"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

// The patch steps as the build runs them: patch-make from a base and a
// target artifact, bin-pack --patch-spec, sign, seal, then patch-check
// rebuilds the target from the base as the box would.
func TestThePatchSteps(t *testing.T) {
	if _, err := exec.LookPath("zstd"); err != nil {
		t.Skip("no zstd command here")
	}
	tmp := t.TempDir()
	target, _ := fixtures.Build(t, fixtures.Options{})
	base := filepath.Join(tmp, "base")
	if err := os.CopyFS(base, os.DirFS(target)); err != nil {
		t.Fatal(err)
	}
	big, err := basepatch.BlobsOf(target)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{big.Root.Digest.Encoded(), big.UKI.Digest.Encoded()} {
		p := filepath.Join(base, "blobs", "sha256", d)
		b, err := os.ReadFile(p) // #nosec G304 -- test-only
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, p, append([]byte("an earlier build "), b...))
	}
	work := filepath.Join(tmp, "patch")
	got, err := runCmd(t, "patch-make", "--base", base, "--target", target, "--out", work)
	if err != nil || !strings.Contains(got, "checked") {
		t.Fatalf("%q %v", got, err)
	}
	raw, err := os.ReadFile(filepath.Join(work, patchSpecFile)) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	var spec patchSpec
	if err := json.Unmarshal(raw, &spec); err != nil || spec.Target.RootSHA256 != big.Root.Digest.Encoded() || spec.Base.RootSize != big.Root.Size+int64(len("an earlier build ")) {
		t.Fatalf("spec %s: %v", raw, err)
	}
	if _, err := os.Stat(filepath.Join(work, "payload", "blobs", "sha256", big.Root.Digest.Encoded())); !os.IsNotExist(err) {
		t.Fatal("the payload carries the root image")
	}
	keys := filepath.Join(tmp, "keys")
	if _, err := runCmd(t, "lab-update-key", "--out", keys); err != nil {
		t.Fatal(err)
	}
	v := spec.Target.Version
	header, err := runCmd(t, "bin-pack", "--layout", filepath.Join(work, "payload"), "--recipient", filepath.Join(keys, "update.pub"), "--unit", "baseOS",
		"--version", v, "--commit", "1a2b3c4", "--channel", "lab", "--patch-spec", filepath.Join(work, patchSpecFile), "--out", filepath.Join(tmp, "bin"))
	if err != nil {
		t.Fatal(err)
	}
	hdr, _ := os.ReadFile(header) // #nosec G304 -- the test's own output
	var h updatepkg.Header
	if err := json.Unmarshal(hdr, &h); err != nil || h.Kind != updatepkg.KindPatch || h.Base == nil || h.Target.FullBin != updatepkg.FileName(updatepkg.Header{Unit: updatepkg.UnitBaseOS, Version: v, Commit: "1a2b3c4", Arch: "amd64", Kind: updatepkg.KindFull, Channel: "lab"}) {
		t.Fatalf("header %s: %v", hdr, err)
	}
	sign := testpki.ECDSA(t)
	writeFile(t, filepath.Join(tmp, "bin", "header.sigstore.json"), sign.BlobBundle(t, hdr))
	writeFile(t, filepath.Join(tmp, "cosign.pub"), sign.PublicPEM)
	pbin, err := runCmd(t, "bin-seal", "--work", filepath.Join(tmp, "bin"), "--bundle", filepath.Join(tmp, "bin", "header.sigstore.json"), "--out", filepath.Join(tmp, "out"))
	if err != nil || !strings.Contains(filepath.Base(pbin), "-baseOS-patch-") {
		t.Fatalf("%s %v", pbin, err)
	}
	rebuilt := filepath.Join(tmp, "rebuilt")
	got, err = runCmd(t, "patch-check", "--base", base, "--release-key", filepath.Join(tmp, "cosign.pub"), "--channel", "lab", "--identity", filepath.Join(keys, "update.key"), "--extract", rebuilt, pbin)
	if err != nil || !strings.HasPrefix(got, "rebuilt "+v) {
		t.Fatalf("%q %v", got, err)
	}
	for _, d := range []string{big.Root.Digest.Encoded(), big.UKI.Digest.Encoded()} {
		a, _ := os.ReadFile(filepath.Join(rebuilt, "blobs", "sha256", d)) // #nosec G304 -- the test's own output
		b, _ := os.ReadFile(filepath.Join(target, "blobs", "sha256", d))  // #nosec G304 -- the fixture
		if len(a) == 0 || string(a) != string(b) {
			t.Fatalf("blob %s isn't the target's", d[:12])
		}
	}
	// Against another base the check refuses, as the box would.
	if _, err := runCmd(t, "patch-check", "--base", target, "--release-key", filepath.Join(tmp, "cosign.pub"), "--channel", "lab", "--identity", filepath.Join(keys, "update.key"), pbin); err == nil || !strings.Contains(err.Error(), "isn't the one the patch was made from") {
		t.Fatalf("another base: %v", err)
	}
}
