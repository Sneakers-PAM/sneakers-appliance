// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v3"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	orasoci "oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Placeholder is the digest sneakers-release pins a service image at until
// the release builds it.
const Placeholder = "sha256:TBD-at-release"

// Build is a service image's source in release.yaml: the release builds
// the image from it (build/release/images.sh).
type Build struct {
	Repository string            `yaml:"repository"`
	Commit     string            `yaml:"commit"`
	Dockerfile string            `yaml:"dockerfile"`
	Context    string            `yaml:"context"`
	Target     string            `yaml:"target"`
	Args       map[string]string `yaml:"args"`
}

// BuildCommitFile, in a built image's layout, is the commit it was built
// from (build/release/images.sh writes it); fill refuses an image whose
// commit isn't the one its build block names.
const BuildCommitFile = "build-commit"

// built is one service image the release built: an OCI layout directory,
// <layouts>/<service>, whose index names exactly one manifest.
type built struct {
	dir    string
	desc   ocispec.Descriptor
	commit string
}

// readBuilt reads every layout in layouts, by service name.
func readBuilt(layouts string) (map[string]built, error) {
	ents, err := os.ReadDir(layouts)
	if err != nil {
		return nil, codes.New(codes.KitBundleMismatch, "the built images %s can't be read: %v", layouts, err)
	}
	out := map[string]built{}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(layouts, e.Name())
		b, err := os.ReadFile(filepath.Join(dir, "index.json")) // #nosec G304 -- a build input directory
		if err != nil {
			return nil, codes.New(codes.KitBundleMismatch, "the built image %s has no OCI layout index: %v", e.Name(), err)
		}
		var idx ocispec.Index
		if err := json.Unmarshal(b, &idx); err != nil || len(idx.Manifests) != 1 {
			return nil, codes.New(codes.KitBundleMismatch, "the built image %s's layout doesn't name exactly one image", e.Name())
		}
		commit, _ := os.ReadFile(filepath.Join(dir, BuildCommitFile)) // #nosec G304 -- as above
		out[e.Name()] = built{dir: dir, desc: idx.Manifests[0], commit: strings.TrimSpace(string(commit))}
	}
	return out, nil
}

// Fill puts the digest of each service image the release built (the
// layouts in layouts, by service name) in place of its placeholder in
// relYAML, and keeps everything else, comments too. It refuses a
// placeholder with no built image, a built image that isn't the digest a
// service already pins, and a built image release.yaml doesn't name.
func Fill(relYAML []byte, layouts string) ([]byte, error) {
	images, err := readBuilt(layouts)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(relYAML, &doc); err != nil {
		return nil, codes.New(codes.KitBundleMismatch, "release.yaml doesn't parse: %v", err)
	}
	if _, err := ParseRelease(relYAML); err != nil {
		return nil, err
	}
	services := lookup(&doc, "spec", "services")
	if services == nil || services.Kind != yaml.MappingNode {
		return nil, codes.New(codes.KitBundleMismatch, "release.yaml pins no services")
	}
	named := map[string]bool{}
	for _, group := range []string{"services", "jobs"} {
		m := lookup(&doc, "spec", group)
		if m == nil || m.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(m.Content); i += 2 {
			name := m.Content[i].Value
			if named[name] {
				return nil, codes.New(codes.KitBundleMismatch, "release.yaml names %s twice among the images it builds", name)
			}
			named[name] = true
			dg := lookup(m.Content[i+1], "digest")
			if dg == nil {
				return nil, codes.New(codes.KitBundleMismatch, "release.yaml's %s.%s has no digest", group, name)
			}
			im, ok := images[name]
			if c := lookup(m.Content[i+1], "build", "commit"); ok && c != nil && im.commit != c.Value {
				return nil, codes.New(codes.KitBundleMismatch, "%s.%s: the image built for it is from commit %q, not the build block's %s", group, name, im.commit, c.Value)
			}
			switch {
			case dg.Value == Placeholder && !ok:
				return nil, codes.New(codes.KitBundleMismatch, "%s.%s is pinned at %s, and no image was built for it", group, name, Placeholder)
			case dg.Value == Placeholder:
				dg.Value = im.desc.Digest.String()
			case ok && dg.Value != im.desc.Digest.String():
				return nil, codes.New(codes.KitBundleMismatch, "%s.%s pins %s, but the image built for it is %s", group, name, dg.Value, im.desc.Digest)
			}
		}
	}
	var stray []string
	for name := range images {
		if !named[name] {
			stray = append(stray, name)
		}
	}
	if len(stray) > 0 {
		sort.Strings(stray)
		return nil, codes.New(codes.KitBundleMismatch, "images were built for %s, which release.yaml doesn't name", strings.Join(stray, ", "))
	}
	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	return []byte(b.String()), nil
}

func lookup(n *yaml.Node, path ...string) *yaml.Node {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	for _, key := range path {
		if n.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				next = n.Content[i+1]
				break
			}
		}
		if next == nil {
			return nil
		}
		n = next
	}
	return n
}

// localSource is the layout under layouts holding dgst, or nil.
func localSource(ctx context.Context, layouts, dgst string) (oras.ReadOnlyTarget, ocispec.Descriptor, error) {
	if layouts == "" {
		return nil, ocispec.Descriptor{}, nil
	}
	images, err := readBuilt(layouts)
	if err != nil {
		return nil, ocispec.Descriptor{}, err
	}
	for _, im := range images {
		if im.desc.Digest.String() != dgst {
			continue
		}
		store, err := orasoci.NewFromFS(ctx, os.DirFS(im.dir))
		if err != nil {
			return nil, ocispec.Descriptor{}, err
		}
		return store, im.desc, nil
	}
	return nil, ocispec.Descriptor{}, nil
}

// Built reports whether an image built in layouts is dgst; never when
// layouts is empty.
func Built(layouts, dgst string) (bool, error) {
	src, _, err := localSource(context.Background(), layouts, dgst)
	return src != nil, err
}

// LocalManifest returns the manifest bytes of the built image dgst, from
// the layouts the release's images job left, checked against dgst.
func LocalManifest(layouts, dgst string) ([]byte, error) {
	ctx := context.Background()
	src, desc, err := localSource(ctx, layouts, dgst)
	if err != nil {
		return nil, err
	}
	if src == nil {
		return nil, codes.New(codes.KitBundleMismatch, "no image built in %s is %s", layouts, dgst)
	}
	b, err := content.FetchAll(ctx, src, desc)
	if err != nil {
		return nil, codes.New(codes.KitBundleMismatch, "the built image %s: %v", dgst, err)
	}
	if got := digest.FromBytes(b).String(); got != dgst {
		return nil, codes.New(codes.KitBundleMismatch, "the built image %s's manifest hashes to %s", dgst, got)
	}
	return b, nil
}

// PushOptions name one built image to push.
type PushOptions struct {
	// Layouts is the directory of built image layouts.
	Layouts string
	// Image is where it goes, without a tag (release.yaml's image).
	Image string
	// Digest is the built image's digest, as the filled release.yaml pins it.
	Digest string
	// Tag is the version tag it also gets.
	Tag string
	// Username and Password log in to the registry; empty for none.
	Username, Password string
	// PlainHTTP talks to the registry without TLS (a lab registry only).
	PlainHTTP bool
}

// PushBuilt pushes the built image o.Digest to o.Image, by its digest and
// with o.Tag, then checks the registry answers that digest with the same
// bytes.
func PushBuilt(ctx context.Context, o PushOptions) error {
	src, desc, err := localSource(ctx, o.Layouts, o.Digest)
	if err != nil {
		return err
	}
	if src == nil {
		return codes.New(codes.KitBundleMismatch, "no image built in %s is %s", o.Layouts, o.Digest)
	}
	dst, err := remote.NewRepository(o.Image)
	if err != nil {
		return codes.New(codes.KitBundleMismatch, "%q isn't an image reference: %v", o.Image, err)
	}
	dst.PlainHTTP = o.PlainHTTP
	client := &auth.Client{Client: retry.DefaultClient, Cache: auth.NewCache()}
	if o.Username != "" {
		client.Credential = auth.StaticCredential(dst.Reference.Registry, auth.Credential{Username: o.Username, Password: o.Password})
	}
	dst.Client = client
	if err := oras.CopyGraph(ctx, src, dst, desc, oras.DefaultCopyGraphOptions); err != nil {
		return fmt.Errorf("bundle: push %s@%s: %w", o.Image, o.Digest, err)
	}
	if err := dst.Tag(ctx, desc, o.Tag); err != nil {
		return fmt.Errorf("bundle: tag %s:%s: %w", o.Image, o.Tag, err)
	}
	back, err := dst.Resolve(ctx, o.Digest)
	if err != nil {
		return codes.New(codes.KitBundleMismatch, "%s@%s can't be resolved after the push: %v", o.Image, o.Digest, err)
	}
	got, err := content.FetchAll(ctx, dst, back)
	if err != nil {
		return codes.New(codes.KitBundleMismatch, "%s@%s after the push: %v", o.Image, o.Digest, err)
	}
	if digest.FromBytes(got).String() != o.Digest {
		return codes.New(codes.KitBundleMismatch, "%s answers %s with other bytes", o.Image, o.Digest)
	}
	return nil
}
