// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package bundle checks the product bundle's airgap images and k0s binary
// against the pinned release (sneakers-release manifest/release.yaml), and
// that a base root carries neither.
//
// An unpacked product bundle holds release.yaml, the k0s binary as k0s,
// the images under images/: one OCI image archive per image, named
// <sha256 hex of the pinned digest>.tar, with the org release-key
// signature of that digest beside it as <hex>.tar.sigstore.json, and the
// stacks k0s applies under manifests/<stack>/*.yaml, and optionally the
// product's brand under brand/ (package brand) and its product.yaml
// (package productspec). Nothing else may be in it.
package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/brand"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
)

// Paths inside the base root tree. ImagesDir and K0sPath are where a root
// carried the product before it shipped as its own bundle; a base root
// must have neither.
const (
	ImagesDir   = "usr/share/sneakers/images"
	K0sPath     = "usr/bin/k0s"
	ReleasePath = "usr/share/sneakers/release/release.yaml"
	SigSuffix   = ".sigstore.json"
)

// Paths inside an unpacked product bundle.
const (
	ProductRelease   = "release.yaml"
	ProductK0s       = "k0s"
	ProductHelm      = "helm"
	ProductImages    = "images"
	ProductManifests = "manifests"
	ProductBrand     = brand.Dir
	// ProductSpec is product.yaml, what the product declares to the
	// appliance (package productspec); optional.
	ProductSpec = productspec.File
)

// Release is the part of release.yaml the bundle check reads. The file is
// owned by sneakers-release; unknown fields are ignored.
type Release struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Version string `yaml:"version"`
	} `yaml:"metadata"`
	Spec struct {
		Services   map[string]Image `yaml:"services"`
		ThirdParty map[string]Image `yaml:"thirdParty"`
		Platform   map[string]Image `yaml:"platform"`
		Kubernetes struct {
			K0s struct {
				Version string            `yaml:"version"`
				SHA256  map[string]string `yaml:"sha256"`
				Images  []Image           `yaml:"images"`
			} `yaml:"k0s"`
			// Helm is the helm binary the bundle carries for the root
			// shell; a release.yaml without it ships none.
			Helm struct {
				Version string            `yaml:"version"`
				SHA256  map[string]string `yaml:"sha256"`
			} `yaml:"helm"`
		} `yaml:"kubernetes"`
	} `yaml:"spec"`
}

// Image is one pinned image.
type Image struct {
	Image  string `yaml:"image"`
	Digest string `yaml:"digest"`
	// Version is the image's version (a service's, which its build is
	// stamped with).
	Version string `yaml:"version"`
	// Build is a service image's source, which the release builds it
	// from; nil for an image the release pulls.
	Build *Build `yaml:"build"`
}

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ParseRelease reads release.yaml.
func ParseRelease(b []byte) (*Release, error) {
	var r Release
	if err := yaml.Unmarshal(b, &r); err != nil {
		return nil, codes.New(codes.KitBundleMismatch, "release.yaml doesn't parse: %v", err)
	}
	if r.APIVersion != "sneakers-pam/v1alpha1" || r.Kind != "Release" {
		return nil, codes.New(codes.KitBundleMismatch, "release.yaml is %s %s, not a sneakers-pam/v1alpha1 Release", r.APIVersion, r.Kind)
	}
	return &r, nil
}

// Images returns every image the bundle must hold, keyed by the hex of its
// digest, valued by a name for messages. The helm test tools in
// spec.tools are not bundled.
func (r *Release) Images() (map[string]string, error) {
	out := map[string]string{}
	add := func(group string, m map[string]Image) error {
		for name, im := range m {
			if !digestRE.MatchString(im.Digest) {
				return codes.New(codes.KitBundleMismatch, "release.yaml pins %s.%s at %q, not a sha256 digest", group, name, im.Digest)
			}
			out[strings.TrimPrefix(im.Digest, "sha256:")] = im.Image
		}
		return nil
	}
	for group, m := range map[string]map[string]Image{"services": r.Spec.Services, "thirdParty": r.Spec.ThirdParty, "platform": r.Spec.Platform} {
		if err := add(group, m); err != nil {
			return nil, err
		}
	}
	k0s := map[string]Image{}
	for i, im := range r.Spec.Kubernetes.K0s.Images {
		k0s[fmt.Sprint(i)] = im
	}
	if err := add("kubernetes.k0s.images", k0s); err != nil {
		return nil, err
	}
	return out, nil
}

// K0sSHA256 is the pinned k0s binary's digest for arch.
func (r *Release) K0sSHA256(arch string) (string, error) {
	s := r.Spec.Kubernetes.K0s.SHA256[arch]
	if len(s) != 64 {
		return "", codes.New(codes.KitBundleMismatch, "release.yaml pins no k0s binary for %s", arch)
	}
	return s, nil
}

// HelmSHA256 is the pinned helm binary's digest for arch, or "" when the
// release ships no helm.
func (r *Release) HelmSHA256(arch string) (string, error) {
	h := r.Spec.Kubernetes.Helm
	if h.Version == "" && len(h.SHA256) == 0 {
		return "", nil
	}
	s := h.SHA256[arch]
	if len(s) != 64 {
		return "", codes.New(codes.KitBundleMismatch, "release.yaml pins helm %s but no helm binary for %s", h.Version, arch)
	}
	return s, nil
}

// CheckImages checks the images directory of fsys (relative to it) against
// rel in both directions, and each image's signature with key.
func CheckImages(fsys fs.FS, dir string, rel *Release, key *ecdsa.PublicKey) error {
	want, err := rel.Images()
	if err != nil {
		return err
	}
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return codes.New(codes.KitBundleMismatch, "the bundle directory %s can't be read: %v", dir, err)
	}
	have := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, ".tar"+SigSuffix):
			continue
		case strings.HasSuffix(name, ".tar"):
			hexd := strings.TrimSuffix(name, ".tar")
			if _, ok := want[hexd]; !ok {
				return codes.New(codes.KitBundleMismatch, "the bundle holds %s, which release.yaml doesn't pin", name)
			}
			have[hexd] = true
		default:
			return codes.New(codes.KitBundleMismatch, "the bundle holds %s, which isn't an image archive", name)
		}
	}
	missing := []string{}
	for hexd, image := range want {
		if !have[hexd] {
			missing = append(missing, image+"@sha256:"+hexd)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return codes.New(codes.KitBundleMismatch, "the bundle lacks %s", strings.Join(missing, ", "))
	}
	for hexd := range have {
		if err := checkArchive(fsys, path.Join(dir, hexd+".tar"), hexd); err != nil {
			return err
		}
		if err := checkImageSignature(fsys, path.Join(dir, hexd+".tar"+SigSuffix), hexd, key); err != nil {
			return err
		}
	}
	return nil
}

// checkArchive requires the archive's index.json to list the pinned digest.
func checkArchive(fsys fs.FS, name, hexd string) error {
	f, err := fsys.Open(name)
	if err != nil {
		return codes.New(codes.KitBundleMismatch, "%s can't be opened: %v", name, err)
	}
	defer func() { _ = f.Close() }()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return codes.New(codes.KitBundleMismatch, "%s has no index.json", name)
		}
		if err != nil {
			return codes.New(codes.KitBundleMismatch, "%s isn't a readable archive: %v", name, err)
		}
		if path.Clean(h.Name) != "index.json" {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, 4<<20))
		if err != nil {
			return codes.New(codes.KitBundleMismatch, "%s: %v", name, err)
		}
		var idx ocispec.Index
		if err := json.Unmarshal(b, &idx); err != nil {
			return codes.New(codes.KitBundleMismatch, "%s has an unreadable index.json: %v", name, err)
		}
		for _, d := range idx.Manifests {
			if d.Digest.String() == "sha256:"+hexd {
				return nil
			}
		}
		return codes.New(codes.KitBundleMismatch, "%s doesn't hold the pinned image sha256:%s", name, hexd)
	}
}

func checkImageSignature(fsys fs.FS, name, hexd string, key *ecdsa.PublicKey) error {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return codes.New(codes.KitImageUnsigned, "image sha256:%s has no signature", hexd)
	}
	return verifyImageSignature(b, hexd, key)
}

// verifyImageSignature checks one sigstore bundle over the image digest hexd.
func verifyImageSignature(b []byte, hexd string, key *ecdsa.PublicKey) error {
	bd, err := sigbundle.Parse(b)
	if err != nil {
		return codes.New(codes.KitImageUnsigned, "image sha256:%s has no readable signature", hexd)
	}
	var d [sha256.Size]byte
	raw, _ := hex.DecodeString(hexd)
	copy(d[:], raw)
	if err := bd.Verify(key, d); err != nil {
		return codes.New(codes.KitImageUnsigned, "image sha256:%s isn't signed by the pinned release key", hexd)
	}
	return nil
}

// CheckRoot checks a base root tree: release.yaml in it is relYAML, and it
// carries no k0s and no images, which ship in the product bundle.
func CheckRoot(fsys fs.FS, relYAML []byte) error {
	if _, err := ParseRelease(relYAML); err != nil {
		return err
	}
	if _, err := fs.Stat(fsys, K0sPath); err == nil {
		return codes.New(codes.KitBundleMismatch, "the base root has /%s; k0s ships in the product bundle", K0sPath)
	}
	if entries, err := fs.ReadDir(fsys, ImagesDir); err == nil && len(entries) > 0 {
		return codes.New(codes.KitBundleMismatch, "the base root holds images in /%s; they ship in the product bundle", ImagesDir)
	}
	inRoot, err := fs.ReadFile(fsys, ReleasePath)
	if err != nil || !bytes.Equal(inRoot, relYAML) {
		return codes.New(codes.KitBundleMismatch, "/%s isn't the verified release.yaml", ReleasePath)
	}
	return nil
}

// CheckProduct checks an unpacked product bundle: only the bundle's own
// entries at the top, k0s (and helm, when release.yaml pins it) is the
// binary its release.yaml pins for arch,
// the images are exactly the pinned ones, each signed with key, the
// stacks are YAML files only, and a brand, when there is one, passes
// brand.Load. It returns the bundle's release.
func CheckProduct(fsys fs.FS, arch string, key *ecdsa.PublicKey) (*Release, error) {
	top, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, codes.New(codes.KitBundleMismatch, "the product bundle can't be read: %v", err)
	}
	for _, e := range top {
		switch e.Name() {
		case ProductRelease, ProductK0s, ProductHelm, ProductImages, ProductManifests, ProductBrand, ProductSpec:
		default:
			return nil, codes.New(codes.KitBundleMismatch, "the product bundle holds %s, which it never carries", e.Name())
		}
	}
	relYAML, err := fs.ReadFile(fsys, ProductRelease)
	if err != nil {
		return nil, codes.New(codes.KitBundleMismatch, "the product bundle has no %s", ProductRelease)
	}
	rel, err := ParseRelease(relYAML)
	if err != nil {
		return nil, err
	}
	want, err := rel.K0sSHA256(arch)
	if err != nil {
		return nil, err
	}
	if err := checkBinary(fsys, ProductK0s, want); err != nil {
		return nil, err
	}
	wantHelm, err := rel.HelmSHA256(arch)
	if err != nil {
		return nil, err
	}
	if wantHelm != "" {
		if err := checkBinary(fsys, ProductHelm, wantHelm); err != nil {
			return nil, err
		}
	} else if _, err := fs.Stat(fsys, ProductHelm); err == nil {
		return nil, codes.New(codes.KitBundleMismatch, "the product bundle holds helm, which its release.yaml doesn't pin")
	}
	if err := CheckImages(fsys, ProductImages, rel, key); err != nil {
		return nil, err
	}
	if err := checkStacks(fsys); err != nil {
		return nil, err
	}
	if err := checkBrand(fsys); err != nil {
		return nil, err
	}
	if err := checkSpec(fsys, rel); err != nil {
		return nil, err
	}
	return rel, nil
}

// checkSpec checks product.yaml, when there is one, and that the bundle
// carries what it names: an image for every component (matched by the
// image's last path element) and every stack a switch gates.
func checkSpec(fsys fs.FS, rel *Release) error {
	if err := productspec.Check(fsys); err != nil {
		return err
	}
	b, err := fs.ReadFile(fsys, ProductSpec)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return codes.New(codes.KitBundleMismatch, "product.yaml can't be read: %v", err)
	}
	spec, err := productspec.Parse(b)
	if err != nil {
		return err
	}
	images, err := rel.Images()
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, im := range images {
		have[path.Base(im)] = true
	}
	for _, c := range spec.Components {
		if !have[c.Image] {
			return codes.New(codes.KitBundleMismatch, "the product bundle has no %s: no image %s is pinned in its release.yaml", c.Name, c.Image)
		}
	}
	for _, w := range spec.Switches {
		for _, st := range w.Stacks {
			if fi, err := fs.Stat(fsys, path.Join(ProductManifests, st)); err != nil || !fi.IsDir() {
				return codes.New(codes.KitBundleMismatch, "the product bundle has no stack %s, which the switch %s turns on", st, w.Name)
			}
		}
	}
	return nil
}

// checkBinary checks that the bundle's binary name has the SHA-256 want.
func checkBinary(fsys fs.FS, name, want string) error {
	f, err := fsys.Open(name)
	if err != nil {
		return codes.New(codes.KitBundleMismatch, "the product bundle has no %s binary", name)
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	_ = f.Close()
	if err != nil {
		return codes.New(codes.KitBundleMismatch, "the product bundle's %s can't be read: %v", name, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return codes.New(codes.KitBundleMismatch, "the product bundle's %s has SHA-256 %s; its release.yaml pins %s", name, got, want)
	}
	return nil
}

// checkBrand checks brand/, when the bundle has one.
func checkBrand(fsys fs.FS) error {
	st, err := fs.Stat(fsys, ProductBrand)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || !st.IsDir() {
		return codes.New(codes.KitBundleMismatch, "the product bundle's %s isn't a directory", ProductBrand)
	}
	sub, err := fs.Sub(fsys, ProductBrand)
	if err != nil {
		return codes.New(codes.KitBundleMismatch, "the product bundle's %s can't be read: %v", ProductBrand, err)
	}
	_, _, err = brand.Load(sub)
	return err
}

// checkStacks allows manifests/<stack>/<file>.yaml and nothing else.
func checkStacks(fsys fs.FS) error {
	stacks, err := fs.ReadDir(fsys, ProductManifests)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return codes.New(codes.KitBundleMismatch, "the product bundle's stacks can't be read: %v", err)
	}
	for _, st := range stacks {
		if !st.IsDir() || !nameRE.MatchString(st.Name()) {
			return codes.New(codes.KitBundleMismatch, "the product bundle's %s/%s isn't a stack directory", ProductManifests, st.Name())
		}
		if st.Name() == productspec.RBACStack || st.Name() == productspec.BoxSecretsStack {
			return codes.New(codes.KitBundleMismatch, "the stack name %s is the appliance's own", st.Name())
		}
		files, err := fs.ReadDir(fsys, path.Join(ProductManifests, st.Name()))
		if err != nil {
			return codes.New(codes.KitBundleMismatch, "the stack %s can't be read: %v", st.Name(), err)
		}
		for _, f := range files {
			if !f.Type().IsRegular() || !strings.HasSuffix(f.Name(), ".yaml") || !nameRE.MatchString(strings.TrimSuffix(f.Name(), ".yaml")) {
				return codes.New(codes.KitBundleMismatch, "the stack %s holds %s, which isn't a YAML manifest", st.Name(), f.Name())
			}
		}
	}
	return nil
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
