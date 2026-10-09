// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package basepatch

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/oci"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
)

// Big is a release's two large blobs: its root image and its UKI.
type Big struct {
	Root, UKI ocispec.Descriptor
}

// BlobsOf finds the root image (root-<v>.img) and the UKI
// (sneakers-<v>.efi) in the artifact at dir by their layer titles.
func BlobsOf(dir string) (Big, error) {
	l, err := oci.Open(dir)
	if err != nil {
		return Big{}, err
	}
	top, err := l.Index()
	if err != nil {
		return Big{}, err
	}
	var b Big
	for _, d := range top.Manifests {
		if d.MediaType != ocispec.MediaTypeImageIndex {
			continue
		}
		idx, err := l.ReadImageIndex(d)
		if err != nil {
			return Big{}, err
		}
		for _, md := range idx.Manifests {
			m, err := l.ReadManifest(md)
			if err != nil {
				return Big{}, err
			}
			for _, layer := range m.Layers {
				t := layer.Annotations[verify.TitleAnnotation]
				switch {
				case strings.HasPrefix(t, "root-") && strings.HasSuffix(t, ".img"):
					b.Root = layer
				case strings.HasPrefix(t, "sneakers-") && strings.HasSuffix(t, ".efi"):
					b.UKI = layer
				}
			}
		}
	}
	if b.Root.Digest == "" || b.UKI.Digest == "" {
		return Big{}, fmt.Errorf("basepatch: %s has no root image and UKI layers", dir)
	}
	return b, nil
}

// DeltaFunc writes the delta of target against base (file paths) to
// delta. The release build's runs `zstd --patch-from`.
type DeltaFunc func(base, target, delta string) error

// MakePayload writes a patch's payload into out from the base and the
// target artifacts: the target layout without its root image and UKI,
// and their deltas made by delta. It checks that both rebuild exactly
// with the box's own decoder, and returns the base and target the patch's
// header names.
func MakePayload(baseDir, targetDir, out string, delta DeltaFunc) (updatepkg.PatchBase, updatepkg.PatchTarget, error) {
	base, err := BlobsOf(baseDir)
	if err != nil {
		return updatepkg.PatchBase{}, updatepkg.PatchTarget{}, err
	}
	target, err := BlobsOf(targetDir)
	if err != nil {
		return updatepkg.PatchBase{}, updatepkg.PatchTarget{}, err
	}
	big := map[string]bool{target.Root.Digest.Encoded(): true, target.UKI.Digest.Encoded(): true}
	if err := copyLayout(targetDir, out, big); err != nil {
		return updatepkg.PatchBase{}, updatepkg.PatchTarget{}, err
	}
	if err := os.MkdirAll(filepath.Join(out, Dir), 0o755); err != nil { // #nosec G301 -- a public payload
		return updatepkg.PatchBase{}, updatepkg.PatchTarget{}, err
	}
	blob := func(dir string, d ocispec.Descriptor) string {
		return filepath.Join(dir, "blobs", "sha256", d.Digest.Encoded())
	}
	for _, f := range []struct {
		b, t  ocispec.Descriptor
		delta string
	}{{base.Root, target.Root, RootDelta}, {base.UKI, target.UKI, UKIDelta}} {
		dp := filepath.Join(out, f.delta)
		if err := delta(blob(baseDir, f.b), blob(targetDir, f.t), dp); err != nil {
			return updatepkg.PatchBase{}, updatepkg.PatchTarget{}, fmt.Errorf("basepatch: make %s: %w", f.delta, err)
		}
		if err := checkFiles(dp, blob(baseDir, f.b), blob(targetDir, f.t)); err != nil {
			return updatepkg.PatchBase{}, updatepkg.PatchTarget{}, fmt.Errorf("basepatch: %s: %w", f.delta, err)
		}
	}
	// The base's hashes are read from its files: what the box compares its
	// running slot and UKI with.
	rootSum, rootSize, err := fileSum(blob(baseDir, base.Root))
	if err != nil {
		return updatepkg.PatchBase{}, updatepkg.PatchTarget{}, err
	}
	ukiSum, _, err := fileSum(blob(baseDir, base.UKI))
	if err != nil {
		return updatepkg.PatchBase{}, updatepkg.PatchTarget{}, err
	}
	return updatepkg.PatchBase{RootSHA256: rootSum, RootSize: rootSize, UKISHA256: ukiSum},
		updatepkg.PatchTarget{RootSHA256: target.Root.Digest.Encoded(), UKISHA256: target.UKI.Digest.Encoded()}, nil
}

func fileSum(p string) (string, int64, error) {
	f, err := os.Open(p) // #nosec G304 -- a build input
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func checkFiles(delta, base, target string) error {
	b, err := os.ReadFile(base) // #nosec G304 -- a build input
	if err != nil {
		return err
	}
	t, err := os.ReadFile(target) // #nosec G304 -- a build input
	if err != nil {
		return err
	}
	d, err := os.Open(delta) // #nosec G304 -- the delta just written
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return Check(d, b, t)
}

// copyLayout copies the layout at src to dst, leaving out the blobs in
// skip.
func copyLayout(src, dst string, skip map[string]bool) error {
	root, err := os.OpenRoot(src)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		to := filepath.Join(dst, filepath.FromSlash(rel))
		if d.IsDir() {
			return os.MkdirAll(to, 0o755) // #nosec G301 -- a public payload
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("basepatch: %s in the layout isn't a regular file", rel)
		}
		if path.Dir(rel) == "blobs/sha256" && skip[path.Base(rel)] {
			return nil
		}
		in, err := root.Open(rel)
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }()
		out, err := os.Create(to) // #nosec G304 -- the payload directory
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = out.Close()
			return err
		}
		return out.Close()
	})
}
