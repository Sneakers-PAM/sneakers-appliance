// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"fmt"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	orasoci "oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/oci"
)

// RegistryOptions tune a registry source.
type RegistryOptions struct {
	// PlainHTTP talks HTTP instead of HTTPS, for a lab registry on
	// loopback.
	PlainHTTP bool
}

// Registry is an artifact in an OCI registry, by tag or digest
// (registry/repository:tag or registry/repository@sha256:...).
func Registry(ref string, o RegistryOptions) Source { return registry{ref: ref, o: o} }

type registry struct {
	ref string
	o   RegistryOptions
}

func (r registry) String() string { return r.ref }

func (r registry) repo() (*remote.Repository, error) {
	repo, err := remote.NewRepository(r.ref)
	if err != nil {
		return nil, codes.New(codes.KitSourceUnreadable, "%q isn't a registry reference: %v", r.ref, err)
	}
	repo.PlainHTTP = r.o.PlainHTTP
	return repo, nil
}

func (r registry) Resolve(ctx context.Context) (digest.Digest, error) {
	repo, err := r.repo()
	if err != nil {
		return "", err
	}
	ref := repo.Reference.Reference
	if ref == "" {
		return "", codes.New(codes.KitSourceUnreadable, "%s names no tag or digest", r.ref)
	}
	desc, err := repo.Resolve(ctx, ref)
	if err != nil {
		return "", codes.New(codes.KitSourceUnreadable, "resolve %s: %v", r.ref, err)
	}
	if desc.MediaType != ocispec.MediaTypeImageIndex {
		return "", codes.New(codes.KitSourceUnreadable, "%s is a %s, not an image index", r.ref, desc.MediaType)
	}
	return desc.Digest, nil
}

func (r registry) Open(context.Context, digest.Digest) (*oci.Layout, error) {
	return nil, fmt.Errorf("verify: a registry source is fetched, not opened")
}

// Fetch copies the index by digest with everything it references and its
// signature referrers into a layout at dir.
func (r registry) Fetch(ctx context.Context, d digest.Digest, dir string) (*oci.Layout, error) {
	repo, err := r.repo()
	if err != nil {
		return nil, err
	}
	desc, err := repo.Resolve(ctx, d.String())
	if err != nil {
		return nil, codes.New(codes.KitSourceUnreadable, "fetch %s@%s: %v", r.ref, d, err)
	}
	store, err := orasoci.New(dir)
	if err != nil {
		return nil, codes.Wrap(codes.KitSourceUnreadable, err)
	}
	opts := oras.DefaultExtendedCopyGraphOptions
	opts.Depth = 1
	opts.FindPredecessors = func(ctx context.Context, src content.ReadOnlyGraphStorage, node ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		preds, err := src.Predecessors(ctx, node)
		if err != nil {
			return nil, err
		}
		var out []ocispec.Descriptor
		for _, p := range preds {
			if p.ArtifactType == SignatureArtifactType {
				out = append(out, p)
			}
		}
		return out, nil
	}
	if err := oras.ExtendedCopyGraph(ctx, repo, store, desc, opts); err != nil {
		return nil, codes.New(codes.KitSourceUnreadable, "fetch %s@%s: %v", r.ref, d, err)
	}
	l, err := oci.Open(dir)
	if err != nil {
		return nil, codes.Wrap(codes.KitSourceUnreadable, err)
	}
	// List exactly the artifact, so the layout resolves to the digest that
	// was fetched and nothing else.
	idx, err := l.Index()
	if err != nil {
		return nil, codes.Wrap(codes.KitSourceUnreadable, err)
	}
	idx.Manifests = []ocispec.Descriptor{desc}
	if err := l.WriteIndex(idx); err != nil {
		return nil, codes.Wrap(codes.KitSourceUnreadable, err)
	}
	return l, nil
}
