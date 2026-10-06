// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
)

func runCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	r := root()
	r.SetOut(&out)
	r.SetErr(&bytes.Buffer{})
	r.SetArgs(args)
	err := r.Execute()
	return strings.TrimSpace(out.String()), err
}

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestTheReleaseSteps runs the .bin steps in the order the release workflow
// does: a lab update key, pack, sign the header (cosign in CI), seal, verify.
func TestTheReleaseSteps(t *testing.T) {
	tmp := t.TempDir()
	keys, layout, work, out, extract := filepath.Join(tmp, "keys"), filepath.Join(tmp, "layout"), filepath.Join(tmp, "work"), filepath.Join(tmp, "out"), filepath.Join(tmp, "x")
	if _, err := runCmd(t, "lab-update-key", "--out", keys); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(keys, "update.key"))
	if err != nil || !strings.Contains(string(key), "LAB ephemeral NOT FOR PRODUCTION") {
		t.Fatalf("update.key isn't labelled lab: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(keys, "update.key")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("update.key mode: %v %v", fi, err)
	}
	if err := os.MkdirAll(layout, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(layout, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`))

	header, err := runCmd(t, "bin-pack", "--layout", layout, "--recipient", filepath.Join(keys, "update.pub"),
		"--version", "0.2.0", "--arch", "amd64", "--channel", "lab", "--out", work)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := os.ReadFile(header) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	sign := testpki.ECDSA(t)
	writeFile(t, filepath.Join(work, "header.sigstore.json"), sign.BlobBundle(t, hdr))
	writeFile(t, filepath.Join(tmp, "cosign.pub"), sign.PublicPEM)

	bin, err := runCmd(t, "bin-seal", "--work", work, "--bundle", filepath.Join(work, "header.sigstore.json"), "--out", out)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(bin) != "sneakers-appliance-0.2.0-amd64-LAB.bin" {
		t.Fatalf("sealed %s", bin)
	}
	got, err := runCmd(t, "bin-verify", "--release-key", filepath.Join(tmp, "cosign.pub"), "--channel", "lab",
		"--identity", filepath.Join(keys, "update.key"), "--extract", extract, bin)
	if err != nil {
		t.Fatal(err)
	}
	if got != "verified sneakers-appliance 0.2.0 amd64 full (lab)" {
		t.Fatalf("verify printed %q", got)
	}
	if b, err := os.ReadFile(filepath.Join(extract, "oci-layout")); err != nil || !strings.Contains(string(b), "imageLayoutVersion") {
		t.Fatalf("extracted %q, %v", b, err)
	}
	if _, err := runCmd(t, "bin-verify", "--release-key", filepath.Join(tmp, "cosign.pub"), "--channel", "production", bin); err == nil || !strings.Contains(err.Error(), "lab package") {
		t.Fatalf("a production verify of a lab package: %v", err)
	}
}
