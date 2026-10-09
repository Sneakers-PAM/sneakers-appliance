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
	if err := bundle.CheckRoot(root, rel); err != nil {
		t.Fatal(err)
	}
}

func TestTheBaseRootCarriesNoProduct(t *testing.T) {
	k := fixtures.LabKeys(t)
	cases := map[string]func(fstest.MapFS){
		"k0s":           fixtures.AddK0sToRoot,
		"an image":      fixtures.AddImageToRoot,
		"other release": func(m fstest.MapFS) { m[bundle.ReleasePath] = &fstest.MapFile{Data: []byte("other")} },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			root, rel := fixtures.RootTree(t, k, "amd64", edit)
			if err := bundle.CheckRoot(root, rel); !codes.Is(err, codes.KitBundleMismatch) {
				t.Fatalf("want KIT_BUNDLE_MISMATCH, got %v", err)
			}
		})
	}
}

func TestCheckProductAcceptsTheFixture(t *testing.T) {
	k := fixtures.LabKeys(t)
	pub, _ := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	tree, _ := fixtures.ProductTree(t, k, "amd64", nil)
	rel, err := bundle.CheckProduct(tree, "amd64", pub)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Spec.Kubernetes.K0s.Version == "" {
		t.Fatal("no k0s version in the checked release")
	}
}

// A release.yaml from before helm shipped pins none, and its bundle has
// none.
func TestCheckProductAcceptsABundleWithoutHelm(t *testing.T) {
	k := fixtures.LabKeys(t)
	pub, _ := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	tree, _ := fixtures.ProductTree(t, k, "amd64", func(m fstest.MapFS) {
		fixtures.UnpinHelm(m)
		delete(m, bundle.ProductHelm)
	})
	if _, err := bundle.CheckProduct(tree, "amd64", pub); err != nil {
		t.Fatal(err)
	}
}

func TestProductCheckBothDirections(t *testing.T) {
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
		"no k0s":         {func(m fstest.MapFS) { delete(m, bundle.ProductK0s) }, codes.KitBundleMismatch},
		"wrong helm":     {fixtures.SwapHelmBinary, codes.KitBundleMismatch},
		"no helm":        {func(m fstest.MapFS) { delete(m, bundle.ProductHelm) }, codes.KitBundleMismatch},
		"unpinned helm":  {fixtures.UnpinHelm, codes.KitBundleMismatch},
		"stray image":    {func(m fstest.MapFS) { m[bundle.ProductImages+"/notes.txt"] = &fstest.MapFile{Data: []byte("x")} }, codes.KitBundleMismatch},
		"stray file":     {func(m fstest.MapFS) { m["notes.txt"] = &fstest.MapFile{Data: []byte("x")} }, codes.KitBundleMismatch},
		"no release":     {func(m fstest.MapFS) { delete(m, bundle.ProductRelease) }, codes.KitBundleMismatch},
		"stack not yaml": {func(m fstest.MapFS) { m[bundle.ProductManifests+"/hello/run.sh"] = &fstest.MapFile{Data: []byte("x")} }, codes.KitBundleMismatch},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tree, _ := fixtures.ProductTree(t, k, "amd64", c.edit)
			if _, err := bundle.CheckProduct(tree, "amd64", pub); !codes.Is(err, c.code) {
				t.Fatalf("want %s, got %v", codes.Symbol(c.code), err)
			}
		})
	}
}

const brandYAML = "apiVersion: sneakers-pam/v1alpha1\nkind: Brand\nlogo: logo.svg\ncolours: {background: \"#0b1f33\", text: \"#ffffff\", accent: \"#ffb000\"}\n"

const brandSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#ffb000"/></svg>`

func addBrand(svg string) func(fstest.MapFS) {
	return func(m fstest.MapFS) {
		m["brand/brand.yaml"] = &fstest.MapFile{Data: []byte(brandYAML), Mode: 0o644}
		m["brand/logo.svg"] = &fstest.MapFile{Data: []byte(svg), Mode: 0o644}
	}
}

// A product bundle may carry its brand; a malformed one refuses the bundle.
func TestAProductBundleMayCarryItsBrand(t *testing.T) {
	k := fixtures.LabKeys(t)
	pub, _ := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	tree, _ := fixtures.ProductTree(t, k, "amd64", addBrand(brandSVG))
	if _, err := bundle.CheckProduct(tree, "amd64", pub); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(fstest.MapFS){
		"script":  addBrand(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
		"no yaml": func(m fstest.MapFS) { m["brand/logo.svg"] = &fstest.MapFile{Data: []byte(brandSVG)} },
		"a file":  func(m fstest.MapFS) { m["brand"] = &fstest.MapFile{Data: []byte(brandYAML)} },
		"stray":   func(m fstest.MapFS) { addBrand(brandSVG)(m); m["brand/run.js"] = &fstest.MapFile{Data: []byte("x")} },
	} {
		tree, _ := fixtures.ProductTree(t, k, "amd64", edit)
		if _, err := bundle.CheckProduct(tree, "amd64", pub); !codes.Is(err, codes.KitBundleMismatch) {
			t.Errorf("%s: want KIT_BUNDLE_MISMATCH, got %v", name, err)
		}
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
