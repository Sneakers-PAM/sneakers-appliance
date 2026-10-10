// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// The release file name shape the boxes before the version-only names
// check a patch's full .bin against: the version (with -g<commit>), then
// -LAB on lab.
var preVersionOnlyName = regexp.MustCompile(`^sneakers-(appliance|appliance-baseOS|appliance-baseOS-patch|appliance-baseWeb|product)-[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?-(amd64|arm64)(-LAB)?\.bin$`)

// packPatchHeader runs bin-pack for a Base OS patch from a hand-made
// patch spec and returns the header it wrote.
func packPatchHeader(t *testing.T, channel string, extra ...string) (updatepkg.Header, error) {
	t.Helper()
	tmp := t.TempDir()
	v := "0.0.0-lab.20261010n4.r20261010141538-g6f08507"
	if channel == "production" {
		v = "0.1.0-rc.2"
	}
	h64 := strings.Repeat("ab", 32)
	spec := patchSpec{Method: updatepkg.MethodZstdPatch,
		Base:   updatepkg.PatchBase{Version: "0.0.0-lab.20261010n3.r20261010105645-ga8df881", RootSHA256: h64, RootSize: 1, UKISHA256: h64},
		Target: updatepkg.PatchTarget{Version: v, RootSHA256: h64, UKISHA256: h64}}
	if channel == "production" {
		spec.Base.Version = "0.1.0-rc.1"
	}
	b, _ := json.Marshal(spec)
	writeFile(t, filepath.Join(tmp, patchSpecFile), b)
	if err := os.MkdirAll(filepath.Join(tmp, "payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(tmp, "payload", "x"), []byte("x"))
	keys := filepath.Join(tmp, "keys")
	if _, err := runCmd(t, "lab-update-key", "--out", keys); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"bin-pack", "--layout", filepath.Join(tmp, "payload"), "--recipient", filepath.Join(keys, "update.pub"), "--unit", "baseOS",
		"--version", v, "--commit", "6f08507", "--channel", channel, "--patch-spec", filepath.Join(tmp, patchSpecFile), "--out", filepath.Join(tmp, "bin")}, extra...)
	header, err := runCmd(t, args...)
	if err != nil {
		return updatepkg.Header{}, err
	}
	raw, err := os.ReadFile(header) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	var h updatepkg.Header
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h, nil
}

// A lab patch built with --previous-full-name names its full release by the
// name the boxes before the version-only names publish and check, so such a
// box takes the patch; by default it names the version-only file.
func TestALabPatchCanNameItsFullReleaseByTheEarlierName(t *testing.T) {
	h, err := packPatchHeader(t, "lab", "--previous-full-name")
	if err != nil {
		t.Fatal(err)
	}
	if !preVersionOnlyName.MatchString(h.Target.FullBin) {
		t.Fatalf("the full .bin %q isn't a name a box before the version-only names takes", h.Target.FullBin)
	}
	full := h
	full.Kind, full.Bases, full.Method, full.Base, full.Target = updatepkg.KindFull, nil, "", nil, nil
	if h.Target.FullBin != updatepkg.PreviousFileName(full) {
		t.Fatalf("full .bin %q, want %q", h.Target.FullBin, updatepkg.PreviousFileName(full))
	}
	d, err := packPatchHeader(t, "lab")
	if err != nil {
		t.Fatal(err)
	}
	if d.Target.FullBin != "sneakers-appliance-baseOS-lab-n4-amd64.bin" {
		t.Fatalf("default lab full .bin %q", d.Target.FullBin)
	}
}

// Production always names the version-only file, and refuses the flag.
func TestAProductionPatchNamesTheVersionOnlyFile(t *testing.T) {
	h, err := packPatchHeader(t, "production")
	if err != nil {
		t.Fatal(err)
	}
	if h.Target.FullBin != "sneakers-appliance-baseOS-0.1.0-rc.2-amd64.bin" {
		t.Fatalf("production full .bin %q", h.Target.FullBin)
	}
	if _, err := packPatchHeader(t, "production", "--previous-full-name"); err == nil || !strings.Contains(err.Error(), "lab") {
		t.Fatalf("production took --previous-full-name: %v", err)
	}
}
