// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bundle_test

import (
	"testing"
	"testing/fstest"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

func TestCheckRootAcceptsTheFixture(t *testing.T) {
	k := fixtures.LabKeys(t)
	root, rel := fixtures.RootTree(t, k, "amd64", nil)
	pub, _ := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	if err := bundle.CheckRoot(root, rel, "amd64", pub); err != nil {
		t.Fatal(err)
	}
}

func TestBundleCheckBothDirections(t *testing.T) {
	k := fixtures.LabKeys(t)
	pub, _ := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	cases := map[string]struct {
		edit func(fstest.MapFS)
		code int
	}{
		"missing image":  {fixtures.RemoveListedImage, codes.KitBundleMismatch},
		"extra image":    {fixtures.AddUnlistedImage, codes.KitBundleMismatch},
		"unsigned image": {fixtures.DropImageSignature, codes.KitImageUnsigned},
		"rogue signed":   {fixtures.ResignImageWithRogue(k), codes.KitImageUnsigned},
		"wrong k0s":      {fixtures.SwapK0sBinary, codes.KitBundleMismatch},
		"stray file":     {func(m fstest.MapFS) { m[bundle.ImagesDir+"/notes.txt"] = &fstest.MapFile{Data: []byte("x")} }, codes.KitBundleMismatch},
		"other release":  {func(m fstest.MapFS) { m[bundle.ReleasePath] = &fstest.MapFile{Data: []byte("other")} }, codes.KitBundleMismatch},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			root, rel := fixtures.RootTree(t, k, "amd64", c.edit)
			if err := bundle.CheckRoot(root, rel, "amd64", pub); !codes.Is(err, c.code) {
				t.Fatalf("want %s, got %v", codes.Symbol(c.code), err)
			}
		})
	}
}

func TestReleaseRefusesPlaceholderDigests(t *testing.T) {
	rel, err := bundle.ParseRelease([]byte("apiVersion: sneakers-pam/v1alpha1\nkind: Release\nspec:\n  services:\n    vault:\n      image: ghcr.io/sneakers-pam/sneakers-vault\n      digest: sha256:TBD-at-release\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rel.Images(); !codes.Is(err, codes.KitBundleMismatch) {
		t.Fatalf("got %v", err)
	}
}
