// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bundle_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

// builtFor writes a single-platform image for arch as an OCI layout in dir,
// built from commit, the way the release's images job leaves each service
// image on that architecture's runner. It returns the manifest and layer
// digests.
func builtFor(t *testing.T, dir, arch, variant, commit string) (digest.Digest, digest.Digest) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o750); err != nil {
		t.Fatal(err)
	}
	put := func(mt string, b []byte) ocispec.Descriptor {
		d := ocispec.Descriptor{MediaType: mt, Digest: digest.FromBytes(b), Size: int64(len(b))}
		if err := os.WriteFile(filepath.Join(dir, "blobs", "sha256", d.Digest.Encoded()), b, 0o600); err != nil {
			t.Fatal(err)
		}
		return d
	}
	layer := make([]byte, 1024)
	_, _ = rand.Read(layer)
	ld := put(ocispec.MediaTypeImageLayer, layer)
	cfg, err := json.Marshal(map[string]string{"architecture": arch, "os": "linux", "variant": variant})
	if err != nil {
		t.Fatal(err)
	}
	cd := put(ocispec.MediaTypeImageConfig, cfg)
	m, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: cd, Layers: []ocispec.Descriptor{ld}})
	if err != nil {
		t.Fatal(err)
	}
	md := put(ocispec.MediaTypeImageManifest, m)
	idx, err := json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{md}})
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"index.json": idx, "oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), bundle.BuildCommitFile: []byte(commit + "\n")} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return md.Digest, ld.Digest
}

const vaultCommit = "2644629a50c138764f89d897bcc4b2e6c78e2924"

// twoArches builds the vault image on each architecture's runner and
// returns the two layouts directories with the manifest and layer digests
// by architecture.
func twoArches(t *testing.T) (amd, arm string, manifests, layers map[string]digest.Digest) {
	t.Helper()
	amd, arm = t.TempDir(), t.TempDir()
	manifests, layers = map[string]digest.Digest{}, map[string]digest.Digest{}
	manifests["amd64"], layers["amd64"] = builtFor(t, filepath.Join(amd, "vault"), "amd64", "", vaultCommit)
	manifests["arm64"], layers["arm64"] = builtFor(t, filepath.Join(arm, "vault"), "arm64", "v8", vaultCommit)
	return amd, arm, manifests, layers
}

func readIndex(t *testing.T, dir string) (ocispec.Descriptor, ocispec.Index) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "index.json")) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	var top ocispec.Index
	if err := json.Unmarshal(b, &top); err != nil || len(top.Manifests) != 1 {
		t.Fatalf("index.json names %d images: %s", len(top.Manifests), b)
	}
	root := top.Manifests[0]
	b, err = os.ReadFile(filepath.Join(dir, "blobs", "sha256", root.Digest.Encoded())) // #nosec G304 -- as above
	if err != nil {
		t.Fatal(err)
	}
	if digest.FromBytes(b) != root.Digest || int64(len(b)) != root.Size {
		t.Fatalf("the index blob isn't %s", root.Digest)
	}
	var idx ocispec.Index
	if err := json.Unmarshal(b, &idx); err != nil {
		t.Fatal(err)
	}
	return root, idx
}

// The release's index step joins each service's per-architecture builds
// into one layout whose root is an image index naming both platforms, and
// the same builds always give the same index.
func TestIndexJoinsTheArchitectures(t *testing.T) {
	amd, arm, manifests, _ := twoArches(t)
	out := filepath.Join(t.TempDir(), "service-images")
	if err := bundle.Index(context.Background(), nil, out, amd, arm); err != nil {
		t.Fatal(err)
	}
	root, idx := readIndex(t, filepath.Join(out, "vault"))
	if root.MediaType != ocispec.MediaTypeImageIndex || idx.MediaType != ocispec.MediaTypeImageIndex {
		t.Fatalf("the root isn't an image index: %s / %s", root.MediaType, idx.MediaType)
	}
	if len(idx.Manifests) != 2 {
		t.Fatalf("the index names %d images", len(idx.Manifests))
	}
	for i, want := range []ocispec.Platform{{OS: "linux", Architecture: "amd64"}, {OS: "linux", Architecture: "arm64", Variant: "v8"}} {
		m := idx.Manifests[i]
		if m.Platform == nil || m.Platform.OS != want.OS || m.Platform.Architecture != want.Architecture || m.Platform.Variant != want.Variant || m.Digest != manifests[want.Architecture] || m.MediaType != ocispec.MediaTypeImageManifest {
			t.Fatalf("index entry %d is %+v (platform %+v), want %s %+v", i, m, m.Platform, manifests[want.Architecture], want)
		}
	}
	commit, err := os.ReadFile(filepath.Join(out, "vault", bundle.BuildCommitFile)) // #nosec G304 -- test output
	if err != nil || strings.TrimSpace(string(commit)) != vaultCommit {
		t.Fatalf("the build commit: %q %v", commit, err)
	}

	again := filepath.Join(t.TempDir(), "service-images")
	if err := bundle.Index(context.Background(), nil, again, arm, amd); err != nil {
		t.Fatal(err)
	}
	if r, _ := readIndex(t, filepath.Join(again, "vault")); r.Digest != root.Digest {
		t.Fatalf("the same builds gave index %s, then %s", root.Digest, r.Digest)
	}
}

func TestIndexRefuses(t *testing.T) {
	amd, arm, _, _ := twoArches(t)
	refused := func(what, want string, layouts ...string) {
		t.Helper()
		err := bundle.Index(context.Background(), nil, filepath.Join(t.TempDir(), "out"), layouts...)
		if !codes.Is(err, codes.KitBundleMismatch) || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v", what, err)
		}
	}
	refused("one architecture", "two", amd)
	refused("the same architecture twice", "linux/amd64", amd, amd)

	missing := t.TempDir()
	builtFor(t, filepath.Join(missing, "web-staff"), "arm64", "v8", vaultCommit)
	refused("a service built on one architecture only", "wasn't built", amd, missing)

	stale := t.TempDir()
	builtFor(t, filepath.Join(stale, "vault"), "arm64", "v8", strings.Repeat("0", 40))
	refused("builds from different commits", "commit", amd, stale)

	out := filepath.Join(t.TempDir(), "out")
	if err := bundle.Index(context.Background(), nil, out, amd, arm); err != nil {
		t.Fatal(err)
	}
	refused("an index layout as an input", "vault", out, arm)
	if err := bundle.Index(context.Background(), nil, out, amd, arm); err == nil {
		t.Fatal("wrote into a layouts directory that isn't empty")
	}
}

// The joined layout goes through the release's path: fill pins the index
// digest, the manifest the sign job countersigns is the index, an amd64
// product bundle carries only the amd64 image under it, and the publish
// job pushes the index with both images.
func TestAnIndexLayoutThroughTheRelease(t *testing.T) {
	amd, arm, manifests, layers := twoArches(t)
	layouts := filepath.Join(t.TempDir(), "service-images")
	if err := bundle.Index(context.Background(), nil, layouts, amd, arm); err != nil {
		t.Fatal(err)
	}
	root, _ := readIndex(t, filepath.Join(layouts, "vault"))

	rel := `apiVersion: sneakers-pam/v1alpha1
kind: Release
spec:
  services:
    vault:
      image: ghcr.io/sneakers-pam/sneakers-vault
      digest: sha256:TBD-at-release
      build:
        repository: Sneakers-PAM/sneakers-vault
        commit: ` + vaultCommit + `
        dockerfile: Dockerfile
        context: .
`
	filled, err := bundle.Fill([]byte(rel), layouts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(filled), "digest: "+root.Digest.String()) {
		t.Fatalf("fill didn't pin the index:\n%s", filled)
	}
	b, err := bundle.LocalManifest(layouts, root.Digest.String())
	if err != nil || digest.FromBytes(b) != root.Digest {
		t.Fatalf("the bytes the sign job countersigns: %v", err)
	}

	k := fixtures.LabKeys(t)
	local := pushed{ref: "ghcr.io/sneakers-pam/sneakers-vault", digest: root.Digest}
	sigs := t.TempDir()
	sign(t, sigs, k, false, local)
	out := filepath.Join(t.TempDir(), "images")
	o := pullOpts(t, releaseFor(t, local), sigs, out, k)
	o.Layouts = layouts
	if err := bundle.Pull(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	n := archiveNames(t, filepath.Join(out, root.Digest.Encoded()+".tar"))
	if !n["blobs/sha256/"+root.Digest.Encoded()] || !n["blobs/sha256/"+layers["amd64"].Encoded()] {
		t.Fatalf("the index or the amd64 layer is missing: %v", n)
	}
	if n["blobs/sha256/"+layers["arm64"].Encoded()] {
		t.Fatal("the arm64 layer was bundled for amd64")
	}

	reg := fixtures.StartRegistry(t)
	image := reg.Host + "/sneakers-pam/sneakers-vault"
	if err := bundle.PushBuilt(context.Background(), bundle.PushOptions{Layouts: layouts, Image: image, Digest: root.Digest.String(), Tag: "0.1.0-rc.3", PlainHTTP: true}); err != nil {
		t.Fatal(err)
	}
	repo, err := remote.NewRepository(image)
	if err != nil {
		t.Fatal(err)
	}
	repo.PlainHTTP = true
	tagged, err := repo.Resolve(context.Background(), "0.1.0-rc.3")
	if err != nil || tagged.Digest != root.Digest {
		t.Fatalf("the version tag names %s (%v), want the index %s", tagged.Digest, err, root.Digest)
	}
	for arch, d := range manifests {
		got, err := bundle.FetchManifest(context.Background(), image, d.String(), true)
		if err != nil || !bytes.Equal(got, mustRead(t, filepath.Join(arm, "vault", "blobs", "sha256", d.Encoded()), filepath.Join(amd, "vault", "blobs", "sha256", d.Encoded()))) {
			t.Fatalf("the %s image wasn't pushed with the index: %v", arch, err)
		}
	}
}

// mustRead reads the first of paths that exists.
func mustRead(t *testing.T, paths ...string) []byte {
	t.Helper()
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil { // #nosec G304 -- test fixtures
			return b
		}
	}
	t.Fatalf("none of %v", paths)
	return nil
}
