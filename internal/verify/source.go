// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/oci"
)

// Source is where an artifact comes from. Resolve turns the reference into
// one digest, once. Open gives a layout that already holds that digest, for
// sources that are layouts; Fetch copies the digest's whole graph and its
// signature into a new layout at dir, checking every blob, so later steps
// read only bytes that were fetched once.
type Source interface {
	Resolve(ctx context.Context) (digest.Digest, error)
	Open(ctx context.Context, d digest.Digest) (*oci.Layout, error)
	Fetch(ctx context.Context, d digest.Digest, dir string) (*oci.Layout, error)
	String() string
}

// Pinned is a layout already fetched for digest d: Resolve returns d without
// looking anything up again.
func Pinned(l *oci.Layout, d digest.Digest) Source { return pinned{l: l, d: d} }

type pinned struct {
	l *oci.Layout
	d digest.Digest
}

func (p pinned) String() string                                           { return "fetched:" + p.d.String() }
func (p pinned) Resolve(context.Context) (digest.Digest, error)           { return p.d, nil }
func (p pinned) Open(context.Context, digest.Digest) (*oci.Layout, error) { return p.l, nil }
func (p pinned) Fetch(ctx context.Context, d digest.Digest, dir string) (*oci.Layout, error) {
	return LocalLayout(p.l.Dir()).Fetch(ctx, d, dir)
}

// LocalLayout is an OCI layout directory, for offline sites. Its index.json
// must list exactly one image index (the artifact).
func LocalLayout(dir string) Source { return localLayout{dir: dir} }

type localLayout struct{ dir string }

func (s localLayout) String() string { return "oci-layout:" + s.dir }

func (s localLayout) Resolve(context.Context) (digest.Digest, error) {
	l, err := oci.Open(s.dir)
	if err != nil {
		return "", codes.Wrap(codes.KitSourceUnreadable, err)
	}
	idx, err := l.Index()
	if err != nil {
		return "", codes.Wrap(codes.KitSourceUnreadable, err)
	}
	var found []digest.Digest
	for _, d := range idx.Manifests {
		if d.MediaType == ocispec.MediaTypeImageIndex {
			found = append(found, d.Digest)
		}
	}
	if len(found) != 1 {
		return "", codes.New(codes.KitSourceUnreadable, "%s lists %d image indexes; it must list exactly one artifact", s.dir, len(found))
	}
	return found[0], nil
}

func (s localLayout) Open(_ context.Context, d digest.Digest) (*oci.Layout, error) {
	l, err := oci.Open(s.dir)
	if err != nil {
		return nil, codes.Wrap(codes.KitSourceUnreadable, err)
	}
	if _, err := descriptorFor(l, d); err != nil {
		return nil, err
	}
	return l, nil
}

func (s localLayout) Fetch(ctx context.Context, d digest.Digest, dir string) (*oci.Layout, error) {
	src, err := s.Open(ctx, d)
	if err != nil {
		return nil, err
	}
	desc, err := descriptorFor(src, d)
	if err != nil {
		return nil, err
	}
	dst, err := oci.Create(dir)
	if err != nil {
		return nil, codes.Wrap(codes.KitSourceUnreadable, err)
	}
	if err := oci.CopyGraph(src, dst, desc, SignatureArtifactType); err != nil {
		return nil, digestOrUnreadable(err)
	}
	return dst, nil
}

// descriptorFor finds d in the layout's index.json.
func descriptorFor(l *oci.Layout, d digest.Digest) (ocispec.Descriptor, error) {
	idx, err := l.Index()
	if err != nil {
		return ocispec.Descriptor{}, codes.Wrap(codes.KitSourceUnreadable, err)
	}
	for _, desc := range idx.Manifests {
		if desc.Digest == d {
			return desc, nil
		}
	}
	return ocispec.Descriptor{}, codes.New(codes.KitSourceUnreadable, "the layout doesn't list %s", d)
}
