// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bundle_test

import (
	"strings"
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

const productYAML = `format: 2
exposed_values:
  - {name: setup-token, secret: sneakers/sneakers-setup-token, key: SETUP_TOKEN, roles: [owner, admin]}
`

// A product bundle may carry product.yaml (format v2); a malformed one,
// or a stack under the appliance's own RBAC stack name, refuses the
// bundle.
func TestAProductBundleMayCarryProductYAML(t *testing.T) {
	k := fixtures.LabKeys(t)
	pub, _ := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	tree, _ := fixtures.ProductTree(t, k, "amd64", func(m fstest.MapFS) {
		m["product.yaml"] = &fstest.MapFile{Data: []byte(productYAML), Mode: 0o644}
	})
	if _, err := bundle.CheckProduct(tree, "amd64", pub); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(fstest.MapFS){
		"a bad role": func(m fstest.MapFS) {
			m["product.yaml"] = &fstest.MapFile{Data: []byte("format: 2\nexposed_values:\n  - {name: a, secret: ns/s, key: K, roles: [root]}\n")}
		},
		"format 1": func(m fstest.MapFS) { m["product.yaml"] = &fstest.MapFile{Data: []byte("format: 1\n")} },
		"the appliance's stack name": func(m fstest.MapFS) {
			m[bundle.ProductManifests+"/sneakers-appliance-exposed/x.yaml"] = &fstest.MapFile{Data: []byte("kind: Role\n")}
		},
	} {
		tree, _ := fixtures.ProductTree(t, k, "amd64", edit)
		if _, err := bundle.CheckProduct(tree, "amd64", pub); !codes.Is(err, codes.KitBundleMismatch) {
			t.Errorf("%s: want KIT_BUNDLE_MISMATCH, got %v", name, err)
		}
	}
}

// A bundle carries every component its product.yaml names (by the image's
// last path element), and every stack its switches gate; one missing
// refuses the bundle, naming it.
func TestABundleCarriesEveryComponentItsProductNames(t *testing.T) {
	k := fixtures.LabKeys(t)
	pub, _ := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	spec := func(extra string) func(fstest.MapFS) {
		return func(m fstest.MapFS) {
			m["product.yaml"] = &fstest.MapFile{Data: []byte("format: 2\ncomponents:\n  - {name: Valkey, image: valkey}\n  - {name: the gateway, image: sneakers-gateway}\n" + extra), Mode: 0o644}
		}
	}
	tree, _ := fixtures.ProductTree(t, k, "amd64", spec("switches:\n  - {name: hi, stacks: [hello]}\n"))
	if _, err := bundle.CheckProduct(tree, "amd64", pub); err != nil {
		t.Fatal(err)
	}
	tree, _ = fixtures.ProductTree(t, k, "amd64", spec("  - {name: the MCP server, image: sneakers-mcp}\n"))
	_, err := bundle.CheckProduct(tree, "amd64", pub)
	if !codes.Is(err, codes.KitBundleMismatch) || !strings.Contains(err.Error(), "the MCP server") {
		t.Fatalf("a missing component: %v", err)
	}
	tree, _ = fixtures.ProductTree(t, k, "amd64", spec("switches:\n  - {name: mcp, stacks: [sneakers-mcp]}\n"))
	_, err = bundle.CheckProduct(tree, "amd64", pub)
	if !codes.Is(err, codes.KitBundleMismatch) || !strings.Contains(err.Error(), "sneakers-mcp") {
		t.Fatalf("a switch's missing stack: %v", err)
	}
}

// A bundle whose product takes an import carries the import Job template
// its product.yaml names, with the migrate image filled in.
func TestABundleCarriesItsImportJob(t *testing.T) {
	k := fixtures.LabKeys(t)
	pub, _ := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	const spec = "format: 2\nexposed_values:\n  - {name: setup-token, secret: ns/s, key: K, roles: [admin], one_time: true, consumed_when: {service: ns/gw:http, path: /setup/state, field: needsSetup, equals: false}}\n" +
		"switches:\n  - {name: import, stacks: [hello]}\nimport: {switch: import, job: import/job.yaml, uid: 65532, setup: setup-token}\n"
	with := func(job string) func(fstest.MapFS) {
		return func(m fstest.MapFS) {
			m["product.yaml"] = &fstest.MapFile{Data: []byte(spec), Mode: 0o644}
			if job != "" {
				m["import/job.yaml"] = &fstest.MapFile{Data: []byte(job), Mode: 0o644}
			}
		}
	}
	tree, _ := fixtures.ProductTree(t, k, "amd64", with("kind: Job\nimage: example.org/sneakers-migrate@sha256:00\nargs: ${ARGS}\n"))
	if _, err := bundle.CheckProduct(tree, "amd64", pub); err != nil {
		t.Fatal(err)
	}
	for name, job := range map[string]string{"no job": "", "the image unfilled": "kind: Job\nimage: \"@MIGRATE_IMAGE@\"\n"} {
		tree, _ := fixtures.ProductTree(t, k, "amd64", with(job))
		if _, err := bundle.CheckProduct(tree, "amd64", pub); !codes.Is(err, codes.KitBundleMismatch) || !strings.Contains(err.Error(), "import") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A bundle with phases carries every phase's own stack, and each workload
// in it carries its phase's labels, on itself and on its pods, as the
// render puts them; the box stops the product by them.
func TestABundleCarriesItsPhaseStacks(t *testing.T) {
	k := fixtures.LabKeys(t)
	pub, _ := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	const spec = "format: 2\nphases:\n  - {name: data, label: The database, stack: app-data, workloads: [app-db]}\n"
	const good = "apiVersion: apps/v1\nkind: StatefulSet\nmetadata:\n  name: app-db\n  namespace: app\n  labels: {sneakers-appliance/phase: data, sneakers-appliance/phase-order: \"1\"}\n" +
		"spec:\n  template:\n    metadata:\n      labels: {app: db, sneakers-appliance/phase: data, sneakers-appliance/phase-order: \"1\"}\n"
	with := func(stack string) func(fstest.MapFS) {
		return func(m fstest.MapFS) {
			m["product.yaml"] = &fstest.MapFile{Data: []byte(spec), Mode: 0o644}
			if stack != "" {
				m[bundle.ProductManifests+"/app-data/app-data.yaml"] = &fstest.MapFile{Data: []byte(stack), Mode: 0o644}
			}
		}
	}
	tree, _ := fixtures.ProductTree(t, k, "amd64", with(good))
	if _, err := bundle.CheckProduct(tree, "amd64", pub); err != nil {
		t.Fatal(err)
	}
	for name, stack := range map[string]string{
		"no phase stack":            "",
		"no labels on the pods":     strings.Replace(good, "app: db, sneakers-appliance/phase: data, sneakers-appliance/phase-order: \"1\"", "app: db", 1),
		"another phase's order":     strings.Replace(good, "phase-order: \"1\"}\nspec", "phase-order: \"2\"}\nspec", 1),
		"a workload no phase names": strings.Replace(good, "name: app-db", "name: app-other", 1),
	} {
		tree, _ := fixtures.ProductTree(t, k, "amd64", with(stack))
		if _, err := bundle.CheckProduct(tree, "amd64", pub); !codes.Is(err, codes.KitBundleMismatch) || !strings.Contains(err.Error(), "app-") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// With phases, a switch's stack that runs a workload must belong to a
// phase (switch_stacks): one no phase places would be placed at k0s's
// start, all at once, and its workloads would hold the cluster step up.
func TestABundleRefusesASwitchStackWithNoPhase(t *testing.T) {
	k := fixtures.LabKeys(t)
	pub, _ := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	const phase = "phases:\n  - {name: data, label: The database, stack: app-data, workloads: [app-db]}\n"
	const db = "apiVersion: apps/v1\nkind: StatefulSet\nmetadata:\n  name: app-db\n  labels: {sneakers-appliance/phase: data, sneakers-appliance/phase-order: \"1\"}\n" +
		"spec:\n  template:\n    metadata:\n      labels: {sneakers-appliance/phase: data, sneakers-appliance/phase-order: \"1\"}\n"
	with := func(sw string) func(fstest.MapFS) {
		return func(m fstest.MapFS) {
			m["product.yaml"] = &fstest.MapFile{Data: []byte("format: 2\nswitches:\n  - {name: mcp, stacks: [app-mcp]}\n" + phase), Mode: 0o644}
			m[bundle.ProductManifests+"/app-data/app-data.yaml"] = &fstest.MapFile{Data: []byte(db), Mode: 0o644}
			m[bundle.ProductManifests+"/app-mcp/app-mcp.yaml"] = &fstest.MapFile{Data: []byte(sw), Mode: 0o644}
		}
	}
	tree, _ := fixtures.ProductTree(t, k, "amd64", with("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: app-mcp-switch}\n"))
	if _, err := bundle.CheckProduct(tree, "amd64", pub); err != nil {
		t.Fatalf("a switch stack with no workload: %v", err)
	}
	tree, _ = fixtures.ProductTree(t, k, "amd64", with("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: app-mcp}\nspec:\n  template:\n    metadata: {}\n"))
	if _, err := bundle.CheckProduct(tree, "amd64", pub); !codes.Is(err, codes.KitBundleMismatch) || !strings.Contains(err.Error(), "app-mcp") {
		t.Fatalf("a switch stack with a workload and no phase: %v", err)
	}
}
