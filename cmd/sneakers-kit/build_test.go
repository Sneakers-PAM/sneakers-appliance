// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

func stamp(t *testing.T, p release.Pins) {
	t.Helper()
	prevVersion := release.Version
	release.Version = fixtures.Version
	restore := release.SetForTest(p.Channel, string(p.ReleaseKeyPEM), string(p.DBCertPEM), string(p.PKCertPEM), string(p.KEKCertPEM))
	t.Cleanup(func() { restore(); release.Version = prevVersion })
}

func TestVerifyCommand(t *testing.T) {
	dir, pins := fixtures.Build(t, fixtures.Options{})
	stamp(t, pins)
	var out, errOut bytes.Buffer
	if code := run([]string{"verify", dir}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "verified "+fixtures.Version+" amd64 (lab)") {
		t.Fatalf("stdout %q", out.String())
	}
}

func TestVerifyCommandRefusal(t *testing.T) {
	dir, pins := fixtures.Build(t, fixtures.Options{Mutate: fixtures.FlipRootByte})
	stamp(t, pins)
	var out, errOut bytes.Buffer
	if code := run([]string{"verify", dir}, &out, &errOut); code == 0 {
		t.Fatal("a flipped root byte must be refused")
	}
	if !strings.Contains(errOut.String(), "KIT_VERITY_MISMATCH (1008)") {
		t.Fatalf("stderr %q", errOut.String())
	}
}

func TestBuildCommandRefusesUnknownFormatAndLeavesOutEmpty(t *testing.T) {
	dir, pins := fixtures.Build(t, fixtures.Options{})
	stamp(t, pins)
	out := filepath.Join(t.TempDir(), "out")
	var so, se bytes.Buffer
	if code := run([]string{"build", dir, "--format", "floppy", "--out", out}, &so, &se); code == 0 {
		t.Fatal("unknown format accepted")
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Fatalf("out %v", entries)
	}
}

func TestSourceFor(t *testing.T) {
	dir := t.TempDir()
	for ref, want := range map[string]string{
		dir:                                 "oci-layout:" + dir,
		"sneakers-os:0.1.0":                 DefaultRepository + ":0.1.0",
		"sha256:" + strings.Repeat("a", 64): DefaultRepository + "@sha256:" + strings.Repeat("a", 64),
		"127.0.0.1:5000/sneakers-os:0.1.0":  "127.0.0.1:5000/sneakers-os:0.1.0",
	} {
		src, err := sourceFor(ref, false)
		if err != nil || src.String() != want {
			t.Errorf("%s: %v %v", ref, src, err)
		}
	}
	if _, err := sourceFor("nonsense", false); err == nil {
		t.Error("a bare word isn't a reference")
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"64G": 64 << 30, "2T": 2 << 40, "512M": 512 << 20, "1048576": 1 << 20} {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "G", "-1G", "x"} {
		if _, err := parseSize(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
