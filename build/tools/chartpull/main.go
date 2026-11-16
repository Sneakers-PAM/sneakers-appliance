// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command chartpull fetches the helm chart release.yaml pins for the
// third-party entry product.yaml's resources section names, by its registry
// digest, into a product bundle's charts/ folder (nothing when product.yaml
// has no resources section): <name>-<version>.tgz and <name>-<version>.manifest.json
// (the bundle check, bundle.CheckProduct, holds both to the pin).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

const chartMedia = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: chartpull <release.yaml> <product.yaml> <out dir>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintln(os.Stderr, "chartpull:", err)
		os.Exit(1)
	}
}

func run(releasePath, productPath, out string) error {
	b, err := os.ReadFile(releasePath) // #nosec G304 G703 -- a build tool reading the file it was handed
	if err != nil {
		return err
	}
	rel, err := bundle.ParseRelease(b)
	if err != nil {
		return err
	}
	pb, err := os.ReadFile(productPath) // #nosec G304 G703 -- a build tool reading the file it was handed
	if err != nil {
		return err
	}
	spec, err := productspec.Parse(pb)
	if err != nil {
		return err
	}
	if spec.Resources == nil {
		return nil
	}
	key := spec.Resources.Chart
	pin := rel.Spec.ThirdParty[key].Chart
	if pin == nil {
		return fmt.Errorf("release.yaml pins no chart for %s", key)
	}
	ref, ok := strings.CutPrefix(pin.Repository, "oci://")
	if !ok {
		return fmt.Errorf("the chart %s is pinned in %s, which isn't an oci:// registry", key, pin.Repository)
	}
	repo, err := remote.NewRepository(strings.TrimSuffix(ref, "/") + "/" + pin.Name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	man, tgz, err := pull(ctx, repo, pin.Digest)
	if err != nil {
		return fmt.Errorf("%s %s: %w", pin.Name, pin.Version, err)
	}
	if err := os.MkdirAll(out, 0o750); err != nil { // #nosec G703 -- a build tool writing under the folder it was handed
		return err
	}
	base := filepath.Join(out, pin.Name+"-"+pin.Version)
	if err := os.WriteFile(base+".manifest.json", man, 0o644); err != nil { // #nosec G306 G703 -- a bundle file under the folder the build handed it, read by the box
		return err
	}
	return os.WriteFile(base+".tgz", tgz, 0o644) // #nosec G306 G703 -- a bundle file under the folder the build handed it, read by the box
}

// pull fetches the manifest with the digest d and the one chart layer it
// names. content.FetchAll holds each to the size and digest it was asked
// for, so a registry can't hand back another chart.
func pull(ctx context.Context, src oras.ReadOnlyTarget, d string) (manifest, chart []byte, err error) {
	md, err := src.Resolve(ctx, d)
	if err != nil {
		return nil, nil, fmt.Errorf("the registry has no manifest %s: %w", d, err)
	}
	manifest, err = content.FetchAll(ctx, src, md)
	if err != nil {
		return nil, nil, err
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return nil, nil, fmt.Errorf("the manifest %s doesn't parse: %w", d, err)
	}
	var layer *ocispec.Descriptor
	for i, l := range m.Layers {
		if l.MediaType != chartMedia {
			continue
		}
		if layer != nil {
			return nil, nil, errors.New("the manifest has more than one chart layer")
		}
		layer = &m.Layers[i]
	}
	if layer == nil {
		return nil, nil, errors.New("the manifest has no chart layer")
	}
	chart, err = content.FetchAll(ctx, src, *layer)
	if err != nil {
		return nil, nil, err
	}
	return manifest, chart, nil
}
