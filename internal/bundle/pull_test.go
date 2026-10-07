// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bundle_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

// pushed is one image on the lab registry.
type pushed struct {
	ref    string
	digest digest.Digest
	// layers by architecture ("" for a single-platform image).
	layers map[string]digest.Digest
}

func push(t *testing.T, repo *remote.Repository, mediaType string, b []byte) ocispec.Descriptor {
	t.Helper()
	d := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(b), Size: int64(len(b))}
	if err := repo.Push(context.Background(), d, bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	return d
}

func manifest(t *testing.T, repo *remote.Repository) (ocispec.Descriptor, digest.Digest) {
	t.Helper()
	layer := make([]byte, 2048)
	_, _ = rand.Read(layer)
	ld := push(t, repo, ocispec.MediaTypeImageLayer, layer)
	cfg := push(t, repo, ocispec.MediaTypeImageConfig, []byte(`{"architecture":"x","os":"linux"}`))
	m, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: cfg, Layers: []ocispec.Descriptor{ld}})
	if err != nil {
		t.Fatal(err)
	}
	md := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(m), Size: int64(len(m))}
	if err := repo.Manifests().Push(context.Background(), md, bytes.NewReader(m)); err != nil {
		t.Fatal(err)
	}
	return md, ld.Digest
}

// lab pushes a single-platform image and a two-architecture index.
func lab(t *testing.T) (single, multi pushed) {
	t.Helper()
	reg := fixtures.StartRegistry(t)
	repo := func(name string) *remote.Repository {
		r, err := remote.NewRepository(reg.Host + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		r.PlainHTTP = true
		return r
	}
	sr := repo("sneakers-pam/sneakers-vault")
	sd, sl := manifest(t, sr)
	single = pushed{ref: reg.Host + "/sneakers-pam/sneakers-vault", digest: sd.Digest, layers: map[string]digest.Digest{"": sl}}

	mr := repo("valkey/valkey")
	multi = pushed{ref: reg.Host + "/valkey/valkey", layers: map[string]digest.Digest{}}
	var ms []ocispec.Descriptor
	for _, arch := range []string{"amd64", "arm64"} {
		d, l := manifest(t, mr)
		d.Platform = &ocispec.Platform{OS: "linux", Architecture: arch}
		ms = append(ms, d)
		multi.layers[arch] = l
	}
	idx, err := json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: ms})
	if err != nil {
		t.Fatal(err)
	}
	id := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromBytes(idx), Size: int64(len(idx))}
	if err := mr.Manifests().Push(context.Background(), id, bytes.NewReader(idx)); err != nil {
		t.Fatal(err)
	}
	multi.digest = id.Digest
	return single, multi
}

func releaseFor(t *testing.T, images ...pushed) *bundle.Release {
	t.Helper()
	var b strings.Builder
	b.WriteString("apiVersion: sneakers-pam/v1alpha1\nkind: Release\nspec:\n  services:\n")
	for i, im := range images {
		b.WriteString("    img" + string(rune('a'+i)) + ":\n      image: " + im.ref + "\n      digest: " + im.digest.String() + "\n")
	}
	rel, err := bundle.ParseRelease([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	return rel
}

func sign(t *testing.T, dir string, k fixtures.Keys, rogue bool, images ...pushed) {
	t.Helper()
	for _, im := range images {
		var sum [sha256.Size]byte
		raw, _ := hex.DecodeString(im.digest.Encoded())
		copy(sum[:], raw)
		key := k.Cosign
		if rogue {
			key = k.RogueCosign
		}
		if err := os.WriteFile(filepath.Join(dir, im.digest.Encoded()+".sigstore.json"), key.DSSEBundle(t, im.ref, sum), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func archiveNames(t *testing.T, p string) map[string]bool {
	t.Helper()
	f, err := os.Open(p) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	names := map[string]bool{}
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Uid != 0 || h.Gid != 0 || !h.ModTime.Equal(time.Unix(1700000000, 0)) {
			t.Fatalf("%s: uid %d gid %d mtime %s", h.Name, h.Uid, h.Gid, h.ModTime)
		}
		names[h.Name] = true
	}
}

func pullOpts(t *testing.T, rel *bundle.Release, sigs, out string, k fixtures.Keys) bundle.PullOptions {
	pub, err := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	if err != nil {
		t.Fatal(err)
	}
	return bundle.PullOptions{Release: rel, Arch: "amd64", Signatures: sigs, Key: pub, Out: out, ModTime: time.Unix(1700000000, 0), PlainHTTP: true}
}

func TestPullBundlesEveryPinnedImageForTheArch(t *testing.T) {
	k := fixtures.LabKeys(t)
	single, multi := lab(t)
	rel := releaseFor(t, single, multi)
	sigs := t.TempDir()
	sign(t, sigs, k, false, single, multi)
	out := filepath.Join(t.TempDir(), "images")
	if err := bundle.Pull(context.Background(), pullOpts(t, rel, sigs, out, k)); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(out)
	if len(ents) != 4 {
		t.Fatalf("want two archives and two signatures, got %d entries", len(ents))
	}
	s := archiveNames(t, filepath.Join(out, single.digest.Encoded()+".tar"))
	if !s["blobs/sha256/"+single.layers[""].Encoded()] || !s["index.json"] || !s["oci-layout"] {
		t.Fatalf("single-platform archive: %v", s)
	}
	m := archiveNames(t, filepath.Join(out, multi.digest.Encoded()+".tar"))
	if !m["blobs/sha256/"+multi.digest.Encoded()] || !m["blobs/sha256/"+multi.layers["amd64"].Encoded()] {
		t.Fatalf("the index or the amd64 layer is missing: %v", m)
	}
	if m["blobs/sha256/"+multi.layers["arm64"].Encoded()] {
		t.Fatal("the arm64 layer was bundled for amd64")
	}

	// The same inputs give the same bytes.
	again := filepath.Join(t.TempDir(), "images")
	if err := bundle.Pull(context.Background(), pullOpts(t, rel, sigs, again, k)); err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		a, _ := os.ReadFile(filepath.Join(out, e.Name()))   // #nosec G304 -- test output
		b, _ := os.ReadFile(filepath.Join(again, e.Name())) // #nosec G304 -- test output
		if !bytes.Equal(a, b) {
			t.Fatalf("%s differs between two pulls", e.Name())
		}
	}

	// Both directions on the finished bundle.
	pub, _ := sigbundle.ParsePublicKey(k.Cosign.PublicPEM)
	if err := os.WriteFile(filepath.Join(out, strings.Repeat("ab", 32)+".tar"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bundle.CheckImages(os.DirFS(out), ".", rel, pub); !codes.Is(err, codes.KitBundleMismatch) {
		t.Fatalf("an unpinned extra archive: want KIT_BUNDLE_MISMATCH, got %v", err)
	}
	_ = os.Remove(filepath.Join(out, strings.Repeat("ab", 32)+".tar"))
	_ = os.Remove(filepath.Join(out, single.digest.Encoded()+".tar"))
	if err := bundle.CheckImages(os.DirFS(out), ".", rel, pub); !codes.Is(err, codes.KitBundleMismatch) {
		t.Fatalf("a missing pinned archive: want KIT_BUNDLE_MISMATCH, got %v", err)
	}
}

func TestPullRefuses(t *testing.T) {
	k := fixtures.LabKeys(t)
	single, multi := lab(t)
	cases := map[string]struct {
		rel   func() *bundle.Release
		sign  func(dir string)
		arch  string
		code  int
		match string
	}{
		"no org signature": {
			rel:   func() *bundle.Release { return releaseFor(t, single, multi) },
			sign:  func(dir string) { sign(t, dir, k, false, single) },
			code:  codes.KitImageUnsigned,
			match: "hasn't countersigned it",
		},
		"another key's signature": {
			rel:  func() *bundle.Release { return releaseFor(t, single) },
			sign: func(dir string) { sign(t, dir, k, true, single) },
			code: codes.KitImageUnsigned,
		},
		"a placeholder digest, as sneakers-release has before its first release": {
			rel: func() *bundle.Release {
				rel, err := bundle.ParseRelease([]byte("apiVersion: sneakers-pam/v1alpha1\nkind: Release\nspec:\n  services:\n    vault:\n      image: ghcr.io/sneakers-pam/sneakers-vault\n      digest: sha256:TBD-at-release\n"))
				if err != nil {
					t.Fatal(err)
				}
				return rel
			},
			sign:  func(string) {},
			code:  codes.KitBundleMismatch,
			match: "not a sha256 digest",
		},
		"no image for the architecture": {
			rel:   func() *bundle.Release { return releaseFor(t, multi) },
			sign:  func(dir string) { sign(t, dir, k, false, multi) },
			arch:  "riscv64",
			code:  codes.KitBundleMismatch,
			match: "no linux/riscv64 image",
		},
		"a digest the registry doesn't have": {
			rel: func() *bundle.Release {
				return releaseFor(t, pushed{ref: single.ref, digest: digest.FromString("not pushed")})
			},
			sign: func(dir string) {
				sign(t, dir, k, false, pushed{ref: single.ref, digest: digest.FromString("not pushed")})
			},
			code:  codes.KitBundleMismatch,
			match: "can't be resolved",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			sigs := t.TempDir()
			c.sign(sigs)
			out := filepath.Join(t.TempDir(), "images")
			o := pullOpts(t, c.rel(), sigs, out, k)
			if c.arch != "" {
				o.Arch = c.arch
			}
			err := bundle.Pull(context.Background(), o)
			if !codes.Is(err, c.code) || !strings.Contains(err.Error(), c.match) {
				t.Fatalf("want %s (%q), got %v", codes.Symbol(c.code), c.match, err)
			}
			if ents, _ := os.ReadDir(out); len(ents) != 0 {
				t.Fatalf("the refused bundle left %d entries", len(ents))
			}
		})
	}
}

// The lab build signs each pinned digest itself, over the manifest or index
// bytes FetchManifest returns; their SHA-256 is the digest.
func TestFetchManifestReturnsThePinnedBytes(t *testing.T) {
	single, multi := lab(t)
	for _, im := range []pushed{single, multi} {
		b, err := bundle.FetchManifest(context.Background(), im.ref, im.digest.String(), true)
		if err != nil {
			t.Fatal(err)
		}
		if got := digest.FromBytes(b); got != im.digest {
			t.Fatalf("%s: the bytes hash to %s, want %s", im.ref, got, im.digest)
		}
	}
	other := digest.FromString("not pushed")
	if _, err := bundle.FetchManifest(context.Background(), single.ref, other.String(), true); !codes.Is(err, codes.KitBundleMismatch) {
		t.Fatalf("a digest the registry doesn't have: want KIT_BUNDLE_MISMATCH, got %v", err)
	}
	if _, err := bundle.FetchManifest(context.Background(), single.ref, "sha256:TBD", true); !codes.Is(err, codes.KitBundleMismatch) {
		t.Fatalf("a placeholder digest: want KIT_BUNDLE_MISMATCH, got %v", err)
	}
}
