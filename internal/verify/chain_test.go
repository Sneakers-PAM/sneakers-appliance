// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"context"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

func chain(t *testing.T, o fixtures.Options) error {
	t.Helper()
	dir, pins := fixtures.Build(t, o)
	_, err := verify.Chain(context.Background(), verify.LocalLayout(dir), pins, verify.Options{Arch: o.Arch, KitVersion: fixtures.Version})
	return err
}

func TestChainPassesAValidFixture(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			dir, pins := fixtures.Build(t, fixtures.Options{Arch: arch})
			m, err := verify.Chain(context.Background(), verify.LocalLayout(dir), pins, verify.Options{Arch: arch, KitVersion: fixtures.Version})
			if err != nil {
				t.Fatal(err)
			}
			if m.Metadata.Version != fixtures.Version || m.Spec.Arch != arch {
				t.Fatalf("manifest %+v", m.Metadata)
			}
		})
	}
}

func TestChainRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate fixtures.Mutation
		code   int
	}{
		{"unsigned", fixtures.DropSignature, codes.KitSigMissing},
		{"wrong signer", fixtures.ResignWithRogueCosign, codes.KitWrongSigner},
		{"swapped layer", fixtures.SwapLayer("root"), codes.KitDigestMismatch},
		{"swapped uki", fixtures.SwapLayer("uki"), codes.KitDigestMismatch},
		{"release.yaml unsigned", fixtures.DropReleaseSignature, codes.KitSigMissing},
		{"release.yaml wrong signer", fixtures.ResignRelease, codes.KitWrongSigner},
		{"manifest digest edited before signing", fixtures.LayerDigestEdit, codes.KitDigestMismatch},
		{"extra file", fixtures.ExtraFile, codes.KitDigestMismatch},
		{"uki re-signed with a rogue db", fixtures.ResignUKIWithRogueDB, codes.KitAuthenticode},
		{"loader re-signed with a rogue db", fixtures.ResignLoaderWithRogueDB, codes.KitAuthenticode},
		{"unsigned uki", fixtures.UnsignedUKI, codes.KitAuthenticode},
		{"one root byte", fixtures.FlipRootByte, codes.KitVerityMismatch},
		{"cmdline names another root", fixtures.CmdlineOtherRootHash, codes.KitVerityMismatch},
		{"k0s in the base root", fixtures.Mutation{Root: fixtures.AddK0sToRoot}, codes.KitBundleMismatch},
		{"an image in the base root", fixtures.Mutation{Root: fixtures.AddImageToRoot}, codes.KitBundleMismatch},
		{"extra certificate in db.esl", fixtures.AppendCertToDBESL, codes.KitWrongSigner},
		{"db.auth signed by PK", fixtures.DBAuthSignedByPK, codes.KitWrongSigner},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := chain(t, fixtures.Options{Arch: "amd64", Mutate: c.mutate}); !codes.Is(err, c.code) {
				t.Fatalf("want %s, got %v", codes.Symbol(c.code), err)
			}
		})
	}
}

func TestChainRefusesLabArtifactInProductionKit(t *testing.T) {
	dir, pins := fixtures.Build(t, fixtures.Options{})
	_, err := verify.Chain(context.Background(), verify.LocalLayout(dir), fixtures.ProductionPins(pins), verify.Options{KitVersion: fixtures.Version})
	if !codes.Is(err, codes.KitChannel) {
		t.Fatalf("want KIT_CHANNEL, got %v", err)
	}
}

func TestChainRefusesMissingArchitecture(t *testing.T) {
	dir, pins := fixtures.Build(t, fixtures.Options{Arch: "amd64"})
	_, err := verify.Chain(context.Background(), verify.LocalLayout(dir), pins, verify.Options{Arch: "arm64", KitVersion: fixtures.Version})
	if !codes.Is(err, codes.KitSourceUnreadable) {
		t.Fatalf("got %v", err)
	}
}

func TestChainArm64Refusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate fixtures.Mutation
		code   int
	}{
		{"boot file not listed", fixtures.Arm64ExtraBootFile, codes.KitDigestMismatch},
		{"cmdline.txt names another root", fixtures.Arm64CmdlineOtherRootHash, codes.KitVerityMismatch},
		{"one root byte", fixtures.FlipRootByte, codes.KitVerityMismatch},
		{"k0s in the base root", fixtures.Mutation{Root: fixtures.AddK0sToRoot}, codes.KitBundleMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := chain(t, fixtures.Options{Arch: "arm64", Mutate: c.mutate}); !codes.Is(err, c.code) {
				t.Fatalf("want %s, got %v", codes.Symbol(c.code), err)
			}
		})
	}
}
