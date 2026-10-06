// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package kit_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	digest "github.com/opencontainers/go-digest"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/kitout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

// marker is a stand-in format: it writes the digest it was handed.
type marker struct{ seen *digest.Digest }

func (marker) Format() string   { return "marker" }
func (marker) Arches() []string { return []string{"amd64", "arm64"} }
func (m marker) Write(_ context.Context, s *verify.State, _ kitout.Options, dir string) error {
	if m.seen != nil {
		*m.seen = s.Digest
	}
	return os.WriteFile(filepath.Join(dir, kitout.BaseName(s)+".marker"), []byte(s.Digest.String()), 0o600)
}

func opts(out string) kitout.Options {
	return kitout.Options{Out: out, KitVersion: fixtures.Version}
}

func TestBuildWritesOnlyOnSuccess(t *testing.T) {
	dir, pins := fixtures.Build(t, fixtures.Options{})
	out := t.TempDir()
	paths, err := kitout.NewWriters(marker{}).Run(context.Background(), verify.LocalLayout(dir), pins, "marker", opts(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || filepath.Base(paths[0]) != "sneakers-"+fixtures.Version+"-amd64-LAB.marker" {
		t.Fatalf("wrote %v", paths)
	}
	entries, _ := os.ReadDir(out)
	if len(entries) != 1 {
		t.Fatalf("out holds %v; the work directory must be gone", entries)
	}
}

// TestRefusedBuildLeavesOutEmpty is the kit refusal suite of spec 1
// Section 6: every mutation gives its exact code and leaves --out empty.
func TestRefusedBuildLeavesOutEmpty(t *testing.T) {
	cases := []struct {
		name   string
		arch   string
		mutate fixtures.Mutation
		pins   func(p release.Pins) release.Pins
		code   int
	}{
		{name: "unsigned", mutate: fixtures.DropSignature, code: codes.KitSigMissing},
		{name: "wrong signer", mutate: fixtures.ResignWithRogueCosign, code: codes.KitWrongSigner},
		{name: "lab against production", pins: fixtures.ProductionPins, code: codes.KitChannel},
		{name: "production against lab", mutate: fixtures.Mutation{Manifest: productionManifest}, code: codes.KitChannel},
		{name: "swapped layer", mutate: fixtures.SwapLayer("root"), code: codes.KitDigestMismatch},
		{name: "re-signed UKI", mutate: fixtures.ResignUKIWithRogueDB, code: codes.KitAuthenticode},
		{name: "one byte of the root", mutate: fixtures.FlipRootByte, code: codes.KitVerityMismatch},
		{name: "one byte of the arm64 root", arch: "arm64", mutate: fixtures.FlipRootByte, code: codes.KitVerityMismatch},
		{name: "extra image", mutate: fixtures.Mutation{Root: fixtures.AddUnlistedImage}, code: codes.KitBundleMismatch},
		{name: "missing image", mutate: fixtures.Mutation{Root: fixtures.RemoveListedImage}, code: codes.KitBundleMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, pins := fixtures.Build(t, fixtures.Options{Arch: c.arch, Mutate: c.mutate})
			if c.pins != nil {
				pins = c.pins(pins)
			}
			out := t.TempDir()
			o := opts(out)
			o.Arch = c.arch
			_, err := kitout.NewWriters(marker{}).Run(context.Background(), verify.LocalLayout(dir), pins, "marker", o)
			if !codes.Is(err, c.code) {
				t.Fatalf("want %s, got %v", codes.Symbol(c.code), err)
			}
			if entries, _ := os.ReadDir(out); len(entries) != 0 {
				t.Fatalf("out not empty: %v", entries)
			}
		})
	}
}

// countingSource counts Resolve calls and moves the tag right after the
// first one.
type countingSource struct {
	verify.Source
	resolves   int
	afterFirst func()
}

func (c *countingSource) Resolve(ctx context.Context) (digest.Digest, error) {
	c.resolves++
	d, err := c.Source.Resolve(ctx)
	if c.resolves == 1 && c.afterFirst != nil {
		c.afterFirst()
	}
	return d, err
}

// TestBuildUsesTheVerifiedBytes pins Review Focus 1: a tag moved between
// resolve and build changes nothing, because the kit fetches by digest
// once and builds from that copy.
func TestBuildUsesTheVerifiedBytes(t *testing.T) {
	reg := fixtures.StartRegistry(t)
	good, pins := fixtures.Build(t, fixtures.Options{})
	reg.Push(t, good, "sneakers-os:"+fixtures.Version)
	moved, _ := fixtures.Build(t, fixtures.Options{Mutate: fixtures.FlipRootByte})
	want, err := verify.LocalLayout(good).Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	src := &countingSource{
		Source:     verify.Registry(reg.Ref("sneakers-os:"+fixtures.Version), verify.RegistryOptions{PlainHTTP: true}),
		afterFirst: func() { reg.Push(t, moved, "sneakers-os:"+fixtures.Version) },
	}
	var seen digest.Digest
	out := t.TempDir()
	if _, err := kitout.NewWriters(marker{seen: &seen}).Run(context.Background(), src, pins, "marker", opts(out)); err != nil {
		t.Fatal(err)
	}
	if src.resolves != 1 {
		t.Fatalf("resolved %d times", src.resolves)
	}
	if seen != want {
		t.Fatalf("built from %s, verified %s", seen, want)
	}
	again, err := verify.Registry(reg.Ref("sneakers-os:"+fixtures.Version), verify.RegistryOptions{PlainHTTP: true}).Resolve(context.Background())
	if err != nil || again == want {
		t.Fatalf("the tag must have moved for this test to mean anything: %s %v", again, err)
	}
}

func TestVerifyFromRegistry(t *testing.T) {
	reg := fixtures.StartRegistry(t)
	dir, pins := fixtures.Build(t, fixtures.Options{})
	reg.Push(t, dir, "sneakers-os:"+fixtures.Version)
	m, err := kitout.Verify(context.Background(), verify.Registry(reg.Ref("sneakers-os:"+fixtures.Version), verify.RegistryOptions{PlainHTTP: true}), pins, opts(""))
	if err != nil || m.Metadata.Version != fixtures.Version {
		t.Fatalf("%v %v", m, err)
	}
	unsigned, pins2 := fixtures.Build(t, fixtures.Options{Mutate: fixtures.DropSignature})
	reg.Push(t, unsigned, "unsigned:"+fixtures.Version)
	if _, err := kitout.Verify(context.Background(), verify.Registry(reg.Ref("unsigned:"+fixtures.Version), verify.RegistryOptions{PlainHTTP: true}), pins2, opts("")); !codes.Is(err, codes.KitSigMissing) {
		t.Fatalf("want KIT_SIG_MISSING, got %v", err)
	}
}

func productionManifest(m *verify.Manifest) { m.Metadata.Channel = release.ChannelProduction }
