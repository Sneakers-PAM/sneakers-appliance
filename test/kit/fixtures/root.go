// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package fixtures

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/squashfs"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verity"
)

// The images the fixture release pins, by group.
var fixtureImages = []struct{ group, name, image string }{
	{"services", "vault", "ghcr.io/sneakers-pam/sneakers-vault"},
	{"services", "gateway", "ghcr.io/sneakers-pam/sneakers-gateway"},
	{"thirdParty", "valkey", "docker.io/valkey/valkey"},
	{"k0s", "pause", "quay.io/k0sproject/pause"},
}

// RootTree returns a small root tree as it would be laid out in the root
// image (k0s, the release and a signed airgap bundle) with the release.yaml
// that pins it. edit, when set, changes the tree after the release is
// written.
func RootTree(t testing.TB, k Keys, arch string, edit func(fstest.MapFS)) (fstest.MapFS, []byte) {
	t.Helper()
	k0s := random(t, 32<<10)
	k0sSum := sha256.Sum256(k0s)
	other := sha256.Sum256(append([]byte("other arch"), k0s...))
	sums := map[string]string{"amd64": hex.EncodeToString(other[:]), "arm64": hex.EncodeToString(other[:])}
	sums[arch] = hex.EncodeToString(k0sSum[:])

	m := fstest.MapFS{
		"sbin/init":    {Data: []byte("init"), Mode: 0o755},
		bundle.K0sPath: {Data: k0s, Mode: 0o755},
	}
	groups := map[string]map[string]map[string]string{"services": {}, "thirdParty": {}}
	var k0sImages []map[string]string
	for _, im := range fixtureImages {
		archive, d := imageArchive(t, im.image)
		hexd := d.Digest.Encoded()
		m[bundle.ImagesDir+"/"+hexd+".tar"] = &fstest.MapFile{Data: archive}
		var sum [sha256.Size]byte
		raw, _ := hex.DecodeString(hexd)
		copy(sum[:], raw)
		m[bundle.ImagesDir+"/"+hexd+".tar"+bundle.SigSuffix] = &fstest.MapFile{Data: k.Cosign.DSSEBundle(t, im.image, sum)}
		entry := map[string]string{"image": im.image, "digest": d.Digest.String()}
		if im.group == "k0s" {
			k0sImages = append(k0sImages, entry)
		} else {
			groups[im.group][im.name] = entry
		}
	}
	rel := map[string]any{
		"apiVersion": "sneakers-pam/v1alpha1",
		"kind":       "Release",
		"metadata":   map[string]string{"version": Version},
		"spec": map[string]any{
			"services":   groups["services"],
			"thirdParty": groups["thirdParty"],
			"kubernetes": map[string]any{"k0s": map[string]any{"version": "v1.36.4+k0s.1", "sha256": sums, "images": k0sImages}},
		},
	}
	relYAML, err := json.Marshal(rel) // JSON is YAML
	must(t, err)
	m[bundle.ReleasePath] = &fstest.MapFile{Data: relYAML}
	if edit != nil {
		edit(m)
	}
	return m, relYAML
}

// imageArchive makes a tiny OCI image archive and returns it with the
// digest of the manifest its index lists.
func imageArchive(t testing.TB, ref string) ([]byte, ocispec.Descriptor) {
	t.Helper()
	layer := random(t, 1024)
	man, err := json.Marshal(ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    ocispec.DescriptorEmptyJSON,
		Layers:    []ocispec.Descriptor{{MediaType: ocispec.MediaTypeImageLayer, Digest: digestOf(layer), Size: int64(len(layer))}},
	})
	must(t, err)
	desc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digestOf(man), Size: int64(len(man)),
		Annotations: map[string]string{ocispec.AnnotationRefName: ref}}
	idx, err := json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{desc}})
	must(t, err)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	put := func(name string, b []byte) {
		must(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg}))
		_, err := tw.Write(b)
		must(t, err)
	}
	put("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
	put("index.json", idx)
	put("blobs/sha256/"+desc.Digest.Encoded(), man)
	put("blobs/sha256/"+digestOf(layer).Encoded(), layer)
	put("blobs/sha256/"+ocispec.DescriptorEmptyJSON.Digest.Encoded(), ocispec.DescriptorEmptyJSON.Data)
	must(t, tw.Close())
	return buf.Bytes(), desc
}

// SquashFS packs fsys into a SquashFS image (zstd), padded to whole 4 KiB
// blocks.
func SquashFS(t testing.TB, fsys fs.FS) []byte {
	t.Helper()
	img := filepath.Join(t.TempDir(), "root.sqfs")
	f, err := os.Create(img) // #nosec G304 -- the test's own temp file
	must(t, err)
	defer func() { _ = f.Close() }()
	sq, err := squashfs.Create(file.New(f, false), 0, 0, 0)
	must(t, err)
	var names []string
	must(t, fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == "." {
			return err
		}
		names = append(names, p)
		return nil
	}))
	sort.Strings(names)
	for _, p := range names {
		st, err := fs.Stat(fsys, p)
		must(t, err)
		if st.IsDir() {
			must(t, sq.Mkdir(p))
			continue
		}
		must(t, sq.Mkdir(path.Dir(p)))
		b, err := fs.ReadFile(fsys, p)
		must(t, err)
		w, err := sq.OpenFile(p, os.O_CREATE|os.O_RDWR)
		must(t, err)
		_, err = w.Write(b)
		must(t, err)
		must(t, w.Close())
	}
	must(t, sq.Finalize(squashfs.FinalizeOptions{Compression: &squashfs.CompressorZstd{}}))
	b, err := os.ReadFile(img) // #nosec G304 -- the test's own temp file
	must(t, err)
	if rem := len(b) % verity.BlockSize; rem != 0 {
		b = append(b, make([]byte, verity.BlockSize-rem)...)
	}
	return b
}

// RootImage builds the root image: the SquashFS of fsys with its verity tree
// appended. It returns the image, the root hash and the hash offset.
func RootImage(t testing.TB, fsys fs.FS) ([]byte, string, int64) {
	t.Helper()
	sq := SquashFS(t, fsys)
	area, root, err := verity.Format(bytes.NewReader(sq), int64(len(sq)))
	must(t, err)
	return append(sq, area...), hex.EncodeToString(root), int64(len(sq))
}

func listed(m fstest.MapFS) []string {
	var out []string
	for name := range m {
		if strings.HasPrefix(name, bundle.ImagesDir+"/") && strings.HasSuffix(name, ".tar") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// RemoveListedImage deletes one pinned image from the bundle.
func RemoveListedImage(m fstest.MapFS) {
	n := listed(m)[0]
	delete(m, n)
	delete(m, n+bundle.SigSuffix)
}

// AddUnlistedImage adds an image release.yaml doesn't pin.
func AddUnlistedImage(m fstest.MapFS) {
	b := []byte("an image nobody pinned")
	m[bundle.ImagesDir+"/"+digestOf(b).Encoded()+".tar"] = &fstest.MapFile{Data: b}
}

// DropImageSignature removes one image's signature.
func DropImageSignature(m fstest.MapFS) { delete(m, listed(m)[0]+bundle.SigSuffix) }

// ResignImageWithRogue signs one image with a key the kit doesn't pin.
func ResignImageWithRogue(k Keys) func(fstest.MapFS) {
	return func(m fstest.MapFS) {
		n := listed(m)[0]
		hexd := strings.TrimSuffix(path.Base(n), ".tar")
		var d [sha256.Size]byte
		raw, _ := hex.DecodeString(hexd)
		copy(d[:], raw)
		m[n+bundle.SigSuffix] = &fstest.MapFile{Data: k.RogueCosign.DSSEBundle(&noFail{}, "rogue", d)}
	}
}

// SwapK0sBinary replaces k0s with another binary.
func SwapK0sBinary(m fstest.MapFS) {
	m[bundle.K0sPath] = &fstest.MapFile{Data: []byte(fmt.Sprintf("not k0s %d", len(m))), Mode: 0o755}
}

func digestOf(b []byte) digest.Digest { return digest.SHA256.FromBytes(b) }
