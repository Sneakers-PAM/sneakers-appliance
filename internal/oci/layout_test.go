// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package oci_test

import (
	"errors"
	"os"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/oci"
)

func TestBlobRoundTripAndTamper(t *testing.T) {
	l, err := oci.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	desc, err := l.WriteBlob("application/octet-stream", []byte("root image bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if b, err := l.ReadBlob(desc); err != nil || string(b) != "root image bytes" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := l.HashBlob(desc); err != nil {
		t.Fatal(err)
	}
	p, _ := l.BlobPath(desc.Digest)
	if err := os.WriteFile(p, []byte("root image bytez"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.ReadBlob(desc); !errors.Is(err, oci.ErrDigest) {
		t.Fatalf("ReadBlob: %v", err)
	}
	if _, err := l.HashBlob(desc); !errors.Is(err, oci.ErrDigest) {
		t.Fatalf("HashBlob: %v", err)
	}
}

func TestOpenRefusesANonLayout(t *testing.T) {
	if _, err := oci.Open(t.TempDir()); err == nil {
		t.Fatal("an empty directory is not a layout")
	}
}

func TestReferrersFindsUnlistedSignature(t *testing.T) {
	l, _ := oci.Create(t.TempDir())
	subject, _ := l.WriteJSON(ocispec.MediaTypeImageIndex, ocispec.Index{MediaType: ocispec.MediaTypeImageIndex})
	layer, _ := l.WriteBlob("application/vnd.dev.sigstore.bundle.v0.3+json", []byte(`{}`))
	m := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		Config:       ocispec.DescriptorEmptyJSON,
		Layers:       []ocispec.Descriptor{layer},
		Subject:      &subject,
	}
	if _, err := l.WriteJSON(ocispec.MediaTypeImageManifest, m); err != nil {
		t.Fatal(err)
	}
	got, err := l.Referrers(subject.Digest, "application/vnd.dev.sigstore.bundle.v0.3+json")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %d referrers, %v", len(got), err)
	}
	if got, _ := l.Referrers(subject.Digest, "other"); len(got) != 0 {
		t.Fatal("artifactType must match")
	}
}
