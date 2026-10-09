// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"archive/tar"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	orasoci "oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// PullOptions shape one bundle build.
type PullOptions struct {
	// Release is the parsed release.yaml.
	Release *Release
	// Arch is the box's architecture (amd64 or arm64): from a multi-arch
	// index, only that platform's manifest and layers are pulled.
	Arch string
	// Signatures is a directory of the org release-key signatures of the
	// pinned digests, one <hex>.sigstore.json per image, as the
	// sneakers-release tag workflow countersigns them.
	Signatures string
	// Key is the org release key that must have signed every image.
	Key *ecdsa.PublicKey
	// Out is the bundle directory; it must be empty or missing.
	Out string
	// ModTime is the time every archive entry carries (SOURCE_DATE_EPOCH).
	ModTime time.Time
	// PlainHTTP talks to registries without TLS (a lab registry only).
	PlainHTTP bool
	// Layouts is a directory of images the release built, an OCI layout
	// per service (build/release/images.sh); a pinned digest found there
	// is taken from it instead of a registry. Optional.
	Layouts string
	Logger  log.Logger
}

// Pull builds the airgap bundle: for every image release.yaml pins, it
// checks the org signature of the pinned digest first, pulls the image by
// that digest for the architecture, and writes it as a reproducible OCI
// archive with the signature beside it. It then checks the bundle against
// the release in both directions. On any refusal Out is left empty.
func Pull(ctx context.Context, o PullOptions) (err error) {
	lg := o.Logger
	if lg == nil {
		lg = log.Nop()
	}
	want, err := o.Release.Images()
	if err != nil {
		return err
	}
	if err := emptyDir(o.Out); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			clearDir(o.Out)
		}
	}()
	hexes := make([]string, 0, len(want))
	for h := range want {
		hexes = append(hexes, h)
	}
	sort.Strings(hexes)
	lg.Info("bundle: start", log.F("images", len(hexes)), log.F("arch", o.Arch))
	sigs := map[string][]byte{}
	for _, h := range hexes {
		b, err := os.ReadFile(filepath.Join(o.Signatures, h+".sigstore.json")) // #nosec G304 -- a build input directory
		if err != nil {
			return codes.New(codes.KitImageUnsigned, "%s@sha256:%s has no org signature in %s; sneakers-release hasn't countersigned it", want[h], h, o.Signatures)
		}
		if err := verifyImageSignature(b, h, o.Key); err != nil {
			return err
		}
		sigs[h] = b
	}
	for _, h := range hexes {
		start := time.Now()
		if err := pullOne(ctx, o, want[h], "sha256:"+h); err != nil {
			lg.Error(err, "bundle: pull failed", log.F("image", want[h]), log.F("digest", h))
			return err
		}
		if err := os.WriteFile(filepath.Join(o.Out, h+".tar"+SigSuffix), sigs[h], 0o644); err != nil { // #nosec G306 -- public signatures in the read-only root
			return err
		}
		lg.Info("bundle: pulled", log.F("image", want[h]), log.F("digest", h), log.F("took", time.Since(start).String()))
	}
	if err := CheckImages(os.DirFS(o.Out), ".", o.Release, o.Key); err != nil {
		return err
	}
	lg.Info("bundle: done", log.F("images", len(hexes)))
	return nil
}

// FetchManifest returns the manifest or index image@dgst names, checked
// against dgst. The lab build signs these bytes for its own bundle.
func FetchManifest(ctx context.Context, image, dgst string, plainHTTP bool) ([]byte, error) {
	if !digestRE.MatchString(dgst) {
		return nil, codes.New(codes.KitBundleMismatch, "%s is pinned at %q, not a sha256 digest", image, dgst)
	}
	repo, err := repository(image, plainHTTP)
	if err != nil {
		return nil, err
	}
	desc, err := repo.Resolve(ctx, dgst)
	if err != nil {
		return nil, codes.New(codes.KitBundleMismatch, "%s@%s can't be resolved: %v", image, dgst, err)
	}
	b, err := content.FetchAll(ctx, repo, desc)
	if err != nil {
		return nil, codes.New(codes.KitBundleMismatch, "%s@%s: %v", image, dgst, err)
	}
	if got := digest.FromBytes(b).String(); got != dgst {
		return nil, codes.New(codes.KitBundleMismatch, "%s@%s returned bytes hashing to %s", image, dgst, got)
	}
	return b, nil
}

func repository(image string, plainHTTP bool) (*remote.Repository, error) {
	ref := image
	if host, rest, ok := strings.Cut(image, "/"); ok && host == "docker.io" {
		ref = "registry-1.docker.io/" + rest
	}
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, codes.New(codes.KitBundleMismatch, "release.yaml names %q, which isn't an image reference: %v", image, err)
	}
	repo.PlainHTTP = plainHTTP
	repo.Client = &auth.Client{Client: retry.DefaultClient, Cache: auth.NewCache()}
	return repo, nil
}

func pullOne(ctx context.Context, o PullOptions, image, dgst string) error {
	repo, root, err := source(ctx, o, image, dgst)
	if err != nil {
		return err
	}
	if root.Digest.String() != dgst {
		return codes.New(codes.KitBundleMismatch, "%s@%s resolved to %s", image, dgst, root.Digest)
	}
	dir, err := os.MkdirTemp("", "bundle-layout-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	store, err := orasoci.NewWithContext(ctx, dir)
	if err != nil {
		return err
	}
	store.AutoSaveIndex = false
	switch root.MediaType {
	case ocispec.MediaTypeImageIndex, "application/vnd.docker.distribution.manifest.list.v2+json":
		// The index blob is kept whole so the pinned digest stays the
		// archive's root; only this architecture's manifest is pulled under
		// it, as `ctr images export --platform` does.
		b, err := content.FetchAll(ctx, repo, root)
		if err != nil {
			return codes.New(codes.KitBundleMismatch, "%s@%s: %v", image, dgst, err)
		}
		var idx ocispec.Index
		if err := json.Unmarshal(b, &idx); err != nil {
			return codes.New(codes.KitBundleMismatch, "%s@%s has an unreadable index: %v", image, dgst, err)
		}
		var pick *ocispec.Descriptor
		for i, m := range idx.Manifests {
			if m.Platform != nil && m.Platform.OS == "linux" && m.Platform.Architecture == o.Arch {
				pick = &idx.Manifests[i]
				break
			}
		}
		if pick == nil {
			return codes.New(codes.KitBundleMismatch, "%s@%s has no linux/%s image", image, dgst, o.Arch)
		}
		if err := oras.CopyGraph(ctx, repo, store, *pick, oras.DefaultCopyGraphOptions); err != nil {
			return codes.New(codes.KitBundleMismatch, "%s@%s (linux/%s): %v", image, dgst, o.Arch, err)
		}
		if err := writeBlob(dir, root.Digest, b); err != nil {
			return err
		}
	default:
		if err := oras.CopyGraph(ctx, repo, store, root, oras.DefaultCopyGraphOptions); err != nil {
			return codes.New(codes.KitBundleMismatch, "%s@%s: %v", image, dgst, err)
		}
	}
	top := ocispec.Descriptor{MediaType: root.MediaType, Digest: root.Digest, Size: root.Size,
		Annotations: map[string]string{ocispec.AnnotationRefName: image + "@" + dgst}}
	return writeArchive(dir, top, filepath.Join(o.Out, strings.TrimPrefix(dgst, "sha256:")+".tar"), o.ModTime)
}

// source is where image@dgst comes from: the layout the release built it
// in, else its registry.
func source(ctx context.Context, o PullOptions, image, dgst string) (oras.ReadOnlyTarget, ocispec.Descriptor, error) {
	local, desc, err := localSource(ctx, o.Layouts, dgst)
	if err != nil || local != nil {
		return local, desc, err
	}
	repo, err := repository(image, o.PlainHTTP)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	root, err := repo.Resolve(ctx, dgst)
	if err != nil {
		return nil, ocispec.Descriptor{}, codes.New(codes.KitBundleMismatch, "%s@%s can't be resolved: %v", image, dgst, err)
	}
	return repo, root, nil
}

func writeBlob(dir string, d digest.Digest, b []byte) error {
	p := filepath.Join(dir, "blobs", d.Algorithm().String(), d.Encoded())
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { // #nosec G301 -- a temporary build layout
		return err
	}
	return os.WriteFile(p, b, 0o644) // #nosec G306 -- as above
}

// writeArchive tars the layout's blobs with a fresh index.json naming only
// top, in name order, root-owned and stamped with mtime, so the same image
// always gives the same bytes.
func writeArchive(dir string, top ocispec.Descriptor, out string, mtime time.Time) error {
	idx, err := json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{top}})
	if err != nil {
		return err
	}
	var blobs []string
	err = filepath.WalkDir(filepath.Join(dir, "blobs"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		blobs = append(blobs, filepath.ToSlash(rel))
		return err
	})
	if err != nil {
		return err
	}
	sort.Strings(blobs)
	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644) // #nosec G302 G304 -- the bundle's own output
	if err != nil {
		return err
	}
	tw := tar.NewWriter(f)
	hdr := func(name string, size int64) *tar.Header {
		return &tar.Header{Name: name, Mode: 0o644, Size: size, Typeflag: tar.TypeReg, ModTime: mtime, Format: tar.FormatUSTAR}
	}
	put := func(name string, b []byte) error {
		if err := tw.WriteHeader(hdr(name, int64(len(b)))); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	err = put("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
	if err == nil {
		err = put("index.json", idx)
	}
	for _, name := range blobs {
		if err != nil {
			break
		}
		err = copyInto(tw, hdr, dir, name)
	}
	if err == nil {
		err = tw.Close()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func copyInto(tw *tar.Writer, hdr func(string, int64) *tar.Header, dir, name string) error {
	src, err := os.Open(filepath.Join(dir, filepath.FromSlash(name))) // #nosec G304 -- a blob in the temporary layout
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	st, err := src.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(hdr(name, st.Size())); err != nil {
		return err
	}
	_, err = io.Copy(tw, src)
	return err
}

func emptyDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- the bundle lands in the read-only root
		return err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(ents) > 0 {
		return fmt.Errorf("bundle: %s isn't empty", dir)
	}
	return nil
}

func clearDir(dir string) {
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		_ = os.RemoveAll(filepath.Join(dir, e.Name()))
	}
}
