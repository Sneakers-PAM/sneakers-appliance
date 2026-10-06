// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package oci reads and writes an OCI image layout on disk (image-spec
// v1.1), checking every blob it reads against its descriptor.
package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// MaxManifestSize bounds the blobs read whole into memory (indexes,
// manifests, small files), and the blobs scanned when looking for
// referrers.
const MaxManifestSize = 4 << 20

// ErrDigest reports a blob whose content doesn't match its descriptor.
var ErrDigest = errors.New("oci: blob does not match its descriptor")

// ErrNotFound reports a blob or manifest the layout doesn't hold.
var ErrNotFound = errors.New("oci: not found")

// Layout is an OCI image layout directory.
type Layout struct {
	dir string
}

// Open opens the layout at dir.
func Open(dir string) (*Layout, error) {
	b, err := os.ReadFile(filepath.Join(dir, ocispec.ImageLayoutFile)) // #nosec G304 -- dir is the layout the operator named
	if err != nil {
		return nil, fmt.Errorf("oci: %s isn't an OCI layout: %w", dir, err)
	}
	var l ocispec.ImageLayout
	if err := json.Unmarshal(b, &l); err != nil || l.Version != ocispec.ImageLayoutVersion {
		return nil, fmt.Errorf("oci: %s has an unreadable oci-layout file", dir)
	}
	return &Layout{dir: dir}, nil
}

// Create makes an empty layout at dir.
func Create(dir string) (*Layout, error) {
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o750); err != nil {
		return nil, err
	}
	b, _ := json.Marshal(ocispec.ImageLayout{Version: ocispec.ImageLayoutVersion})
	if err := os.WriteFile(filepath.Join(dir, ocispec.ImageLayoutFile), b, 0o600); err != nil {
		return nil, err
	}
	l := &Layout{dir: dir}
	return l, l.WriteIndex(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex})
}

// Dir is the layout's directory.
func (l *Layout) Dir() string { return l.dir }

// Index reads index.json.
func (l *Layout) Index() (ocispec.Index, error) {
	var idx ocispec.Index
	b, err := os.ReadFile(filepath.Join(l.dir, ocispec.ImageIndexFile))
	if err != nil {
		return idx, err
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		return idx, fmt.Errorf("oci: index.json: %w", err)
	}
	return idx, nil
}

// WriteIndex replaces index.json.
func (l *Layout) WriteIndex(idx ocispec.Index) error {
	b, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(l.dir, ocispec.ImageIndexFile), b, 0o600)
}

// BlobPath is where the blob with digest d lives.
func (l *Layout) BlobPath(d digest.Digest) (string, error) {
	if err := d.Validate(); err != nil || d.Algorithm() != digest.SHA256 {
		return "", fmt.Errorf("oci: unsupported digest %q", d)
	}
	return filepath.Join(l.dir, "blobs", "sha256", d.Encoded()), nil
}

// ReadBlob reads a small blob whole and checks it against desc.
func (l *Layout) ReadBlob(desc ocispec.Descriptor) ([]byte, error) {
	if desc.Size > MaxManifestSize || desc.Size < 0 {
		return nil, fmt.Errorf("oci: blob %s is %d bytes, too large to read whole", desc.Digest, desc.Size)
	}
	p, err := l.BlobPath(desc.Digest)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p) // #nosec G304 -- the path is built from a validated digest inside the layout
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: blob %s", ErrNotFound, desc.Digest)
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxManifestSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != desc.Size || digest.SHA256.FromBytes(b) != desc.Digest {
		return nil, fmt.Errorf("%w: %s", ErrDigest, desc.Digest)
	}
	return b, nil
}

// HashBlob streams the blob for desc and returns its SHA-256 (lowercase
// hex). It fails with ErrDigest when the content doesn't match desc.
func (l *Layout) HashBlob(desc ocispec.Descriptor) (string, error) {
	p, err := l.BlobPath(desc.Digest)
	if err != nil {
		return "", err
	}
	f, err := os.Open(p) // #nosec G304 -- the path is built from a validated digest inside the layout
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: blob %s", ErrNotFound, desc.Digest)
		}
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if n != desc.Size || sum != desc.Digest.Encoded() {
		return sum, fmt.Errorf("%w: %s", ErrDigest, desc.Digest)
	}
	return sum, nil
}

// OpenBlob opens the blob for desc for reading. The caller checks it.
func (l *Layout) OpenBlob(desc ocispec.Descriptor) (*os.File, error) {
	p, err := l.BlobPath(desc.Digest)
	if err != nil {
		return nil, err
	}
	return os.Open(p) // #nosec G304 -- the path is built from a validated digest inside the layout
}

// WriteBlob stores b and returns its descriptor.
func (l *Layout) WriteBlob(mediaType string, b []byte) (ocispec.Descriptor, error) {
	d := digest.SHA256.FromBytes(b)
	p, err := l.BlobPath(d)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return ocispec.Descriptor{}, err
	}
	return ocispec.Descriptor{MediaType: mediaType, Digest: d, Size: int64(len(b))}, nil
}

// WriteJSON marshals v and stores it as a blob.
func (l *Layout) WriteJSON(mediaType string, v any) (ocispec.Descriptor, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return l.WriteBlob(mediaType, b)
}

// ReadManifest reads and decodes an image manifest.
func (l *Layout) ReadManifest(desc ocispec.Descriptor) (ocispec.Manifest, error) {
	var m ocispec.Manifest
	b, err := l.ReadBlob(desc)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("oci: manifest %s: %w", desc.Digest, err)
	}
	if m.MediaType != ocispec.MediaTypeImageManifest {
		return m, fmt.Errorf("oci: %s is %q, not an image manifest", desc.Digest, m.MediaType)
	}
	return m, nil
}

// ReadImageIndex reads and decodes an image index.
func (l *Layout) ReadImageIndex(desc ocispec.Descriptor) (ocispec.Index, error) {
	var idx ocispec.Index
	b, err := l.ReadBlob(desc)
	if err != nil {
		return idx, err
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		return idx, fmt.Errorf("oci: index %s: %w", desc.Digest, err)
	}
	if idx.MediaType != ocispec.MediaTypeImageIndex {
		return idx, fmt.Errorf("oci: %s is %q, not an image index", desc.Digest, idx.MediaType)
	}
	return idx, nil
}

// Referrer is a manifest whose subject is another node, with its own
// descriptor.
type Referrer struct {
	Descriptor ocispec.Descriptor
	Manifest   ocispec.Manifest
}

// Referrers returns the manifests in the layout whose subject is d and whose
// artifactType is artifactType. It reads every small blob, so a referrer
// copied in by any tool is found whether or not index.json lists it.
func (l *Layout) Referrers(d digest.Digest, artifactType string) ([]Referrer, error) {
	entries, err := os.ReadDir(filepath.Join(l.dir, "blobs", "sha256"))
	if err != nil {
		return nil, err
	}
	var out []Referrer
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > MaxManifestSize || info.Size() == 0 {
			continue
		}
		bd := digest.NewDigestFromEncoded(digest.SHA256, e.Name())
		if bd.Validate() != nil {
			continue
		}
		desc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: bd, Size: info.Size()}
		b, err := l.ReadBlob(desc)
		if err != nil || !strings.HasPrefix(strings.TrimSpace(string(b)), "{") {
			continue
		}
		var m ocispec.Manifest
		if json.Unmarshal(b, &m) != nil || m.MediaType != ocispec.MediaTypeImageManifest || m.Subject == nil {
			continue
		}
		if m.Subject.Digest == d && m.ArtifactType == artifactType {
			desc.ArtifactType = artifactType
			out = append(out, Referrer{Descriptor: desc, Manifest: m})
		}
	}
	return out, nil
}

// CopyGraph copies root (an image index or manifest), everything it
// references, and every manifest in src that names root as its subject with
// one of the given artifact types, from src into dst, checking each blob
// against its descriptor on the way. dst's index.json then lists root and
// the referrers.
func CopyGraph(src, dst *Layout, root ocispec.Descriptor, referrerTypes ...string) error {
	if err := copyNode(src, dst, root); err != nil {
		return err
	}
	listed := []ocispec.Descriptor{root}
	for _, at := range referrerTypes {
		refs, err := src.Referrers(root.Digest, at)
		if err != nil {
			return err
		}
		for _, r := range refs {
			if err := copyNode(src, dst, r.Descriptor); err != nil {
				return err
			}
			listed = append(listed, r.Descriptor)
		}
	}
	idx, err := dst.Index()
	if err != nil {
		return err
	}
	idx.Manifests = append(idx.Manifests, listed...)
	return dst.WriteIndex(idx)
}

func copyNode(src, dst *Layout, d ocispec.Descriptor) error {
	switch d.MediaType {
	case ocispec.MediaTypeImageIndex:
		idx, err := src.ReadImageIndex(d)
		if err != nil {
			return err
		}
		for _, m := range idx.Manifests {
			if err := copyNode(src, dst, m); err != nil {
				return err
			}
		}
	case ocispec.MediaTypeImageManifest:
		m, err := src.ReadManifest(d)
		if err != nil {
			return err
		}
		for _, b := range append([]ocispec.Descriptor{m.Config}, m.Layers...) {
			if err := copyBlob(src, dst, b); err != nil {
				return err
			}
		}
	}
	return copyBlob(src, dst, d)
}

// copyBlob streams one blob, hashing as it goes, and renames it into place
// only when it matches its descriptor.
func copyBlob(src, dst *Layout, d ocispec.Descriptor) error {
	to, err := dst.BlobPath(d.Digest)
	if err != nil {
		return err
	}
	if _, err := os.Stat(to); err == nil {
		return nil
	}
	in, err := src.OpenBlob(d)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: blob %s", ErrNotFound, d.Digest)
		}
		return err
	}
	defer func() { _ = in.Close() }()
	return dst.WriteBlobFrom(d, in)
}

// WriteBlobFrom stores the blob for d from r, checking its size and digest.
func (l *Layout) WriteBlobFrom(d ocispec.Descriptor, r io.Reader) error {
	to, err := l.BlobPath(d.Digest)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(to), ".partial-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), r)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != d.Size || hex.EncodeToString(h.Sum(nil)) != d.Digest.Encoded() {
		return fmt.Errorf("%w: %s", ErrDigest, d.Digest)
	}
	return os.Rename(tmp.Name(), to)
}
