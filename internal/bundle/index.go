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

	log "github.com/Bugs5382/go-log"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	orasoci "oras.land/oras-go/v2/content/oci"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Index joins the service images each architecture's images job built
// (platforms: one layouts directory per architecture, an OCI layout per
// service holding one single-platform image) into out, one OCI layout per
// service whose root is an image index naming every architecture's image,
// with the build commit kept. The index entries are in platform order, so
// the same builds always give the same index digest. It refuses fewer than
// two architectures, an architecture given twice, a service missing from
// one of them, builds of one service from different commits, and an input
// that isn't a single-platform image.
func Index(ctx context.Context, lg log.Logger, out string, platforms ...string) error {
	if lg == nil {
		lg = log.Nop()
	}
	lg.Info("index: start", log.F("architectures", len(platforms)), log.F("out", out))
	if len(platforms) < 2 {
		return codes.New(codes.KitBundleMismatch, "an index needs the layouts of two or more architectures, got %d", len(platforms))
	}
	if err := emptyDir(out); err != nil {
		return err
	}
	perArch := make([]map[string]built, len(platforms))
	for i, dir := range platforms {
		images, err := readBuilt(dir)
		if err != nil {
			return err
		}
		perArch[i] = images
	}
	names := map[string]bool{}
	for _, images := range perArch {
		for n := range images {
			names[n] = true
		}
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		if err := indexOne(ctx, lg, out, name, platforms, perArch); err != nil {
			lg.Error(err, "index: refused", log.F("service", name))
			clearDir(out)
			return err
		}
	}
	lg.Info("index: done", log.F("services", len(sorted)))
	return nil
}

// platformOf reads a single-platform image's platform from its config.
func platformOf(ctx context.Context, src content.ReadOnlyStorage, desc ocispec.Descriptor, where string) (ocispec.Platform, error) {
	if desc.MediaType != ocispec.MediaTypeImageManifest && desc.MediaType != "application/vnd.docker.distribution.manifest.v2+json" {
		return ocispec.Platform{}, codes.New(codes.KitBundleMismatch, "%s is a %s, not a single-platform image", where, desc.MediaType)
	}
	b, err := content.FetchAll(ctx, src, desc)
	if err != nil {
		return ocispec.Platform{}, codes.New(codes.KitBundleMismatch, "%s: %v", where, err)
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return ocispec.Platform{}, codes.New(codes.KitBundleMismatch, "%s has an unreadable manifest: %v", where, err)
	}
	b, err = content.FetchAll(ctx, src, m.Config)
	if err != nil {
		return ocispec.Platform{}, codes.New(codes.KitBundleMismatch, "%s's config: %v", where, err)
	}
	var cfg ocispec.Platform
	if err := json.Unmarshal(b, &cfg); err != nil || cfg.OS == "" || cfg.Architecture == "" {
		return ocispec.Platform{}, codes.New(codes.KitBundleMismatch, "%s's config names no os and architecture", where)
	}
	return ocispec.Platform{OS: cfg.OS, Architecture: cfg.Architecture, Variant: cfg.Variant}, nil
}

func platformString(p ocispec.Platform) string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

func indexOne(ctx context.Context, lg log.Logger, out, name string, platforms []string, perArch []map[string]built) error {
	dir := filepath.Join(out, name)
	store, err := orasoci.NewWithContext(ctx, dir)
	if err != nil {
		return err
	}
	store.AutoSaveIndex = false
	commit := ""
	seen := map[string]string{}
	var entries []ocispec.Descriptor
	for i, images := range perArch {
		im, ok := images[name]
		if !ok {
			return codes.New(codes.KitBundleMismatch, "%s wasn't built in %s", name, platforms[i])
		}
		switch {
		case im.commit == "":
			return codes.New(codes.KitBundleMismatch, "%s in %s records no build commit", name, platforms[i])
		case commit == "":
			commit = im.commit
		case im.commit != commit:
			return codes.New(codes.KitBundleMismatch, "%s was built from commit %s in one layout and %s in %s", name, commit, im.commit, platforms[i])
		}
		src, err := orasoci.NewFromFS(ctx, os.DirFS(im.dir))
		if err != nil {
			return err
		}
		where := fmt.Sprintf("%s in %s", name, platforms[i])
		p, err := platformOf(ctx, src, im.desc, where)
		if err != nil {
			return err
		}
		ps := platformString(p)
		if other, dup := seen[ps]; dup {
			return codes.New(codes.KitBundleMismatch, "%s: %s and %s are both %s", name, other, platforms[i], ps)
		}
		seen[ps] = platforms[i]
		lg.Debug("index: image", log.F("service", name), log.F("platform", ps), log.F("digest", im.desc.Digest.String()), log.F("from", platforms[i]))
		if err := oras.CopyGraph(ctx, src, store, im.desc, oras.DefaultCopyGraphOptions); err != nil {
			return codes.New(codes.KitBundleMismatch, "%s: %v", where, err)
		}
		entries = append(entries, ocispec.Descriptor{MediaType: im.desc.MediaType, Digest: im.desc.Digest, Size: im.desc.Size, Platform: &p})
	}
	sort.Slice(entries, func(a, b int) bool {
		return platformString(*entries[a].Platform) < platformString(*entries[b].Platform)
	})
	idx, err := json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: entries})
	if err != nil {
		return err
	}
	root := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromBytes(idx), Size: int64(len(idx))}
	if err := writeBlob(dir, root.Digest, idx); err != nil {
		return err
	}
	top, err := json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{root}})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), top, 0o644); err != nil { // #nosec G306 -- a public image layout
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, BuildCommitFile), []byte(commit+"\n"), 0o644); err != nil { // #nosec G306 -- as above
		return err
	}
	plats := make([]string, 0, len(entries))
	for _, e := range entries {
		plats = append(plats, platformString(*e.Platform))
	}
	lg.Info("index: joined", log.F("service", name), log.F("digest", root.Digest.String()), log.F("platforms", strings.Join(plats, ", ")), log.F("commit", commit))
	return nil
}
