// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
)

// publish puts a chart archive and its manifest in a store, as a registry
// would hold them, and returns the manifest's digest.
func publish(t *testing.T, store *memory.Store, tgz []byte) (string, []byte) {
	t.Helper()
	ctx := context.Background()
	cfg := content.NewDescriptorFromBytes("application/vnd.cncf.helm.config.v1+json", []byte("{}"))
	layer := content.NewDescriptorFromBytes(chartMedia, tgz)
	for d, b := range map[*ocispec.Descriptor][]byte{&cfg: []byte("{}"), &layer: tgz} {
		if err := store.Push(ctx, *d, bytes.NewReader(b)); err != nil {
			t.Fatal(err)
		}
	}
	man, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: cfg, Layers: []ocispec.Descriptor{layer}})
	if err != nil {
		t.Fatal(err)
	}
	md := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, man)
	if err := store.Push(ctx, md, bytes.NewReader(man)); err != nil {
		t.Fatal(err)
	}
	// A registry resolves a digest reference; the store only tags.
	if err := store.Tag(ctx, md, md.Digest.String()); err != nil {
		t.Fatal(err)
	}
	return md.Digest.String(), man
}

func TestPullReturnsTheManifestAndTheChartItNames(t *testing.T) {
	store := memory.New()
	tgz := []byte("chart archive bytes")
	d, man := publish(t, store, tgz)
	gotMan, gotTGZ, err := pull(context.Background(), store, d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotMan, man) || !bytes.Equal(gotTGZ, tgz) {
		t.Fatalf("pulled %q and %q", gotMan, gotTGZ)
	}
}

func TestPullRefusesADigestTheRegistryDoesNotHold(t *testing.T) {
	store := memory.New()
	publish(t, store, []byte("chart"))
	other := digest.FromString("another manifest").String()
	if _, _, err := pull(context.Background(), store, other); err == nil {
		t.Fatal("pulled a manifest the store doesn't hold")
	}
}

func TestPullRefusesAManifestWithNoChartLayer(t *testing.T) {
	store := memory.New()
	ctx := context.Background()
	man, _ := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: ocispec.DescriptorEmptyJSON})
	md := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, man)
	if err := store.Push(ctx, md, bytes.NewReader(man)); err != nil {
		t.Fatal(err)
	}
	if err := store.Tag(ctx, md, md.Digest.String()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pull(ctx, store, md.Digest.String()); err == nil {
		t.Fatal("pulled a chart from a manifest with none")
	}
}
