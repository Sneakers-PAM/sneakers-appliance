// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
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

// TestTheProductBundleSteps packs an unpacked product bundle the way the
// release and lab builds do, seals it, verifies and extracts it (which
// checks its k0s and images), and writes the index a mirror serves.
func TestTheProductBundleSteps(t *testing.T) {
	tmp := t.TempDir()
	keys, tree, work, out, extract := filepath.Join(tmp, "keys"), filepath.Join(tmp, "tree"), filepath.Join(tmp, "work"), filepath.Join(tmp, "out"), filepath.Join(tmp, "x")
	if _, err := runCmd(t, "lab-update-key", "--out", keys); err != nil {
		t.Fatal(err)
	}
	k := fixtures.LabKeys(t)
	writeTree(t, tree, k)
	writeFile(t, filepath.Join(tmp, "cosign.pub"), k.Cosign.PublicPEM)

	if got, err := runCmd(t, "product-check", "--dir", tree, "--release-key", filepath.Join(tmp, "cosign.pub"), "--arch", "amd64"); err != nil || !strings.HasPrefix(got, "checked product bundle") {
		t.Fatalf("product-check: %q, %v", got, err)
	}
	header, err := runCmd(t, "bin-pack", "--layout", tree, "--recipient", filepath.Join(keys, "update.pub"),
		"--version", "0.2.0", "--arch", "amd64", "--channel", "lab", "--kind", "product", "--base", "0.2.0", "--base", "0.2.1", "--out", work)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := os.ReadFile(header) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(work, "header.sigstore.json"), k.Cosign.BlobBundle(t, hdr))
	bin, err := runCmd(t, "bin-seal", "--work", work, "--bundle", filepath.Join(work, "header.sigstore.json"), "--out", out)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(bin) != "sneakers-product-0.2.0-amd64-LAB.bin" {
		t.Fatalf("sealed %s", bin)
	}
	got, err := runCmd(t, "bin-verify", "--release-key", filepath.Join(tmp, "cosign.pub"), "--channel", "lab",
		"--identity", filepath.Join(keys, "update.key"), "--extract", extract, bin)
	if err != nil || got != "verified sneakers-product 0.2.0 amd64 product (lab)" {
		t.Fatalf("verify printed %q, %v", got, err)
	}
	if fi, err := os.Stat(filepath.Join(extract, "k0s")); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("extracted k0s: %v %v", fi, err)
	}

	idx := filepath.Join(out, updatepkg.IndexName)
	if _, err := runCmd(t, "product-index", "--out", idx, bin); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(idx) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	var index updatepkg.Index
	if err := json.Unmarshal(b, &index); err != nil || len(index.Products) != 1 {
		t.Fatalf("index %s: %v", b, err)
	}
	e := index.Products[0]
	if e.Version != "0.2.0" || e.File != "sneakers-product-0.2.0-amd64-LAB.bin" || e.Channel != "lab" || len(e.Bases) != 2 || e.Size == 0 {
		t.Fatalf("entry %+v", e)
	}
}

func TestBinVerifyChecksAnExtractedProductBundle(t *testing.T) {
	tmp := t.TempDir()
	keys, tree, work, out := filepath.Join(tmp, "keys"), filepath.Join(tmp, "tree"), filepath.Join(tmp, "work"), filepath.Join(tmp, "out")
	if _, err := runCmd(t, "lab-update-key", "--out", keys); err != nil {
		t.Fatal(err)
	}
	k := fixtures.LabKeys(t)
	writeTree(t, tree, k)
	// A k0s other than the one release.yaml pins: signed and sealed all the
	// same, the unpacked bundle is refused.
	writeFile(t, filepath.Join(tree, "k0s"), []byte("not the pinned k0s"))
	writeFile(t, filepath.Join(tmp, "cosign.pub"), k.Cosign.PublicPEM)
	header, err := runCmd(t, "bin-pack", "--layout", tree, "--recipient", filepath.Join(keys, "update.pub"),
		"--version", "0.2.0", "--channel", "lab", "--kind", "product", "--base", "0.2.0", "--out", work)
	if err != nil {
		t.Fatal(err)
	}
	hdr, _ := os.ReadFile(header) // #nosec G304 -- the test's own output
	writeFile(t, filepath.Join(work, "header.sigstore.json"), k.Cosign.BlobBundle(t, hdr))
	bin, err := runCmd(t, "bin-seal", "--work", work, "--bundle", filepath.Join(work, "header.sigstore.json"), "--out", out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runCmd(t, "bin-verify", "--release-key", filepath.Join(tmp, "cosign.pub"), "--channel", "lab",
		"--identity", filepath.Join(keys, "update.key"), "--extract", filepath.Join(tmp, "x"), bin); !codes.Is(err, codes.KitBundleMismatch) {
		t.Fatalf("want KIT_BUNDLE_MISMATCH, got %v", err)
	}
}

// writeTree writes the fixture product bundle to dir.
func writeTree(t *testing.T, dir string, k fixtures.Keys) {
	t.Helper()
	m, _ := fixtures.ProductTree(t, k, "amd64", nil)
	for name, f := range m {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, p, f.Data)
	}
}

func TestBinPackWritesAProductBundlesBaseRange(t *testing.T) {
	tmp := t.TempDir()
	keys, tree, work := filepath.Join(tmp, "keys"), filepath.Join(tmp, "tree"), filepath.Join(tmp, "work")
	if _, err := runCmd(t, "lab-update-key", "--out", keys); err != nil {
		t.Fatal(err)
	}
	writeTree(t, tree, fixtures.LabKeys(t))
	header, err := runCmd(t, "bin-pack", "--layout", tree, "--recipient", filepath.Join(keys, "update.pub"),
		"--version", "0.4.0", "--channel", "lab", "--kind", "product", "--min-base", "0.2.0", "--max-base", "0.3.0", "--out", work)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(header) // #nosec G304 -- the test's own output
	var h updatepkg.Header
	if err := json.Unmarshal(b, &h); err != nil || h.MinBase != "0.2.0" || h.MaxBase != "0.3.0" || len(h.Bases) != 0 {
		t.Fatalf("header %s: %v", b, err)
	}
	if _, err := runCmd(t, "bin-pack", "--layout", tree, "--recipient", filepath.Join(keys, "update.pub"),
		"--version", "0.4.0", "--channel", "lab", "--kind", "product", "--min-base", "0.3.0", "--max-base", "0.2.0", "--out", filepath.Join(tmp, "w2")); !codes.Is(err, codes.UpgradeFormat) {
		t.Fatalf("a range that ends before it starts: want UPGRADE_FORMAT, got %v", err)
	}
}

// product-check names the brand it found, and warns when its colours fail
// the contrast check and the base colours stay.
func TestProductCheckReportsTheBrand(t *testing.T) {
	tmp := t.TempDir()
	tree := filepath.Join(tmp, "tree")
	k := fixtures.LabKeys(t)
	writeTree(t, tree, k)
	writeFile(t, filepath.Join(tmp, "cosign.pub"), k.Cosign.PublicPEM)
	check := func() (string, error) {
		return runCmd(t, "product-check", "--dir", tree, "--release-key", filepath.Join(tmp, "cosign.pub"), "--arch", "amd64")
	}
	if got, err := check(); err != nil || !strings.HasSuffix(got, "no brand") {
		t.Fatalf("%q %v", got, err)
	}
	if err := os.MkdirAll(filepath.Join(tree, "brand"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(tree, "brand", "logo.svg"), []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>`))
	writeFile(t, filepath.Join(tree, "brand", "brand.yaml"), []byte("apiVersion: sneakers-pam/v1alpha1\nkind: Brand\nlogo: logo.svg\ncolours: {background: \"#0b1f33\", text: \"#ffffff\", accent: \"#ffb000\"}\n"))
	if got, err := check(); err != nil || !strings.HasSuffix(got, "brand: logo.svg (image/svg+xml), colours #0b1f33 #ffffff #ffb000") {
		t.Fatalf("%q %v", got, err)
	}
	writeFile(t, filepath.Join(tree, "brand", "brand.yaml"), []byte("apiVersion: sneakers-pam/v1alpha1\nkind: Brand\nlogo: logo.svg\ncolours: {background: \"#0b1f33\", text: \"#203040\", accent: \"#ffb000\"}\n"))
	if got, err := check(); err != nil || !strings.Contains(got, "warning: the brand's text on its background has contrast") || !strings.HasSuffix(got, "brand: logo.svg (image/svg+xml), base colours") {
		t.Fatalf("%q %v", got, err)
	}
	writeFile(t, filepath.Join(tree, "brand", "logo.svg"), []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`))
	if _, err := check(); err == nil {
		t.Fatal("a logo with a script passed the check")
	}
}

// The index lists base releases too, in its base section, next to the
// product bundles; a product-only index reads as before.
func TestTheIndexListsBaseReleases(t *testing.T) {
	tmp := t.TempDir()
	keys, layout, work, out := filepath.Join(tmp, "keys"), filepath.Join(tmp, "layout"), filepath.Join(tmp, "work"), filepath.Join(tmp, "out")
	if _, err := runCmd(t, "lab-update-key", "--out", keys); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(layout, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(layout, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`))
	header, err := runCmd(t, "bin-pack", "--layout", layout, "--recipient", filepath.Join(keys, "update.pub"),
		"--version", "0.3.0", "--arch", "amd64", "--channel", "lab", "--out", work)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := os.ReadFile(header) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	sign := testpki.ECDSA(t)
	writeFile(t, filepath.Join(work, "header.sigstore.json"), sign.BlobBundle(t, hdr))
	bin, err := runCmd(t, "bin-seal", "--work", work, "--bundle", filepath.Join(work, "header.sigstore.json"), "--out", out)
	if err != nil {
		t.Fatal(err)
	}
	idx := filepath.Join(out, updatepkg.IndexName)
	if _, err := runCmd(t, "product-index", "--out", idx, bin); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(idx) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	var index updatepkg.Index
	if err := json.Unmarshal(b, &index); err != nil || len(index.Products) != 0 || len(index.Base) != 1 {
		t.Fatalf("index %s: %v", b, err)
	}
	e := index.Base[0]
	if e.Version != "0.3.0" || e.Kind != "full" || e.File != "sneakers-appliance-0.3.0-amd64-LAB.bin" || e.Channel != "lab" || e.Size == 0 {
		t.Fatalf("entry %+v", e)
	}
}

// sealUnit packs, signs and seals a layout as a unit's .bin with extra
// bin-pack flags and returns its path.
func sealUnit(t *testing.T, tmp string, sealFlags []string, packFlags ...string) string {
	t.Helper()
	keys, layout, work, out := filepath.Join(tmp, "keys"), filepath.Join(tmp, "layout"), filepath.Join(tmp, "work"), filepath.Join(tmp, "out")
	if _, err := os.Stat(filepath.Join(keys, "update.pub")); err != nil {
		if _, err := runCmd(t, "lab-update-key", "--out", keys); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(layout, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(layout, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`))
	_ = os.RemoveAll(work)
	header, err := runCmd(t, append([]string{"bin-pack", "--layout", layout, "--recipient", filepath.Join(keys, "update.pub"), "--arch", "amd64", "--channel", "lab", "--out", work}, packFlags...)...)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := os.ReadFile(header) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(work, "header.sigstore.json"), testpki.ECDSA(t).BlobBundle(t, hdr))
	bin, err := runCmd(t, append([]string{"bin-seal", "--work", work, "--bundle", filepath.Join(work, "header.sigstore.json"), "--out", out}, sealFlags...)...)
	if err != nil {
		t.Fatal(err)
	}
	return bin
}

// The units' .bin files carry their unit, commit, inputs and requires,
// take their new names, and land in the index's lists; the bridge copy
// is the same bytes under the old name, in the legacy base section.
func TestTheUnitsSteps(t *testing.T) {
	tmp := t.TempDir()
	const v = "0.0.0-lab.20261012m-g1a2b3c4"
	inputs := strings.Repeat("e", 64)
	osBin := sealUnit(t, tmp, []string{"--bridge"}, "--unit", "baseOS", "--version", v, "--commit", "1a2b3c4", "--inputs", inputs, "--epoch", "1")
	if filepath.Base(osBin) != "sneakers-appliance-baseOS-"+v+"-amd64-LAB.bin" {
		t.Fatalf("sealed %s", osBin)
	}
	bridge := filepath.Join(filepath.Dir(osBin), "sneakers-appliance-"+v+"-amd64-LAB.bin")
	a, _ := os.ReadFile(osBin)  // #nosec G304 -- the test's own output
	b, _ := os.ReadFile(bridge) // #nosec G304 -- the test's own output
	if len(a) == 0 || !bytes.Equal(a, b) {
		t.Fatal("the bridge copy isn't the same bytes")
	}
	webBin := sealUnit(t, tmp, nil, "--unit", "baseWeb", "--version", v, "--commit", "1a2b3c4", "--requires-baseos-min", "0.0.0-0", "--requires-baseos-before", "0.1.0-0")
	if filepath.Base(webBin) != "sneakers-appliance-baseWeb-"+v+"-amd64-LAB.bin" {
		t.Fatalf("sealed %s", webBin)
	}
	idx := filepath.Join(tmp, updatepkg.IndexName)
	if _, err := runCmd(t, "index", "--out", idx, "--bridge", osBin, osBin, webBin); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(idx) // #nosec G304 -- the test's own output
	var index updatepkg.Index
	if err := json.Unmarshal(raw, &index); err != nil || index.Format != 2 || len(index.BaseOS) != 1 || len(index.BaseWeb) != 1 || len(index.Base) != 1 {
		t.Fatalf("index %s: %v", raw, err)
	}
	if e := index.BaseOS[0]; e.Inputs != inputs || e.Commit != "1a2b3c4" || e.File != filepath.Base(osBin) {
		t.Fatalf("Base OS entry %+v", e)
	}
	if e := index.BaseWeb[0]; e.Requires[updatepkg.UnitBaseOS].Before != "0.1.0-0" {
		t.Fatalf("Base Web entry %+v", e)
	}
	if e := index.Base[0]; e.File != filepath.Base(bridge) {
		t.Fatalf("bridge entry %+v", e)
	}
	if _, err := runCmd(t, "index", "--out", idx, "--bridge", webBin, webBin); err == nil {
		t.Fatal("a Base Web file was listed as a bridge")
	}
}
