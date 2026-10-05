// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package fixtures builds small but complete lab artifacts for the kit's
// tests: an OCI layout with every release file, signed with throwaway keys
// made once per test binary. Mutations break one thing each, either before
// signing (so the artifact signature still holds) or after.
package fixtures

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sort"
	"sync"
	"testing"

	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/oci"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
)

// Version is the fixture release's version.
const Version = "0.1.0"

// Keys are the lab keys of one test binary.
type Keys struct {
	Cosign, RogueCosign  testpki.ECKey
	PK, KEK, DB, RogueDB testpki.Cert
}

var (
	keysOnce sync.Once
	keys     Keys
)

// LabKeys returns the test binary's lab keys, made on first use.
func LabKeys(t testing.TB) Keys {
	t.Helper()
	keysOnce.Do(func() {
		keys = Keys{
			Cosign: testpki.ECDSA(t), RogueCosign: testpki.ECDSA(t),
			PK: testpki.SelfSigned(t, "PK"), KEK: testpki.SelfSigned(t, "KEK"),
			DB: testpki.SelfSigned(t, "db"), RogueDB: testpki.SelfSigned(t, "rogue-db"),
		}
	})
	return keys
}

// Pins are the lab pins matching LabKeys.
func (k Keys) Pins() release.Pins {
	return release.Pins{
		Channel:       release.ChannelLab,
		ReleaseKeyPEM: k.Cosign.PublicPEM,
		DBCertPEM:     k.DB.PEM,
		PKCertPEM:     k.PK.PEM,
		KEKCertPEM:    k.KEK.PEM,
	}
}

// Parts are the release files before they're laid out and signed.
type Parts struct {
	Keys     Keys
	Files    map[string][]byte
	Manifest *verify.Manifest
}

// Mutation breaks one thing about the fixture.
type Mutation struct {
	// Files edits the release files before appliance.yaml is written.
	Files func(p *Parts)
	// Manifest edits appliance.yaml after the digests are filled in.
	Manifest func(m *verify.Manifest)
	// SignArtifact replaces the artifact signature; nil signs with the lab
	// release key, and Unsigned leaves it unsigned.
	SignArtifact func(k Keys, d [sha256.Size]byte) []byte
	Unsigned     bool
	// After tampers with the finished layout.
	After func(t testing.TB, l *oci.Layout)
}

// Options choose the fixture.
type Options struct {
	Arch   string // amd64 (default) or arm64
	Mutate Mutation
}

// Build writes a lab artifact as an OCI layout in a temporary directory and
// returns the directory and the pins that verify it.
func Build(t testing.TB, o Options) (string, release.Pins) {
	t.Helper()
	if o.Arch == "" {
		o.Arch = "amd64"
	}
	k := LabKeys(t)
	p := &Parts{Keys: k, Files: baseFiles(t, k, o.Arch)}
	if o.Mutate.Files != nil {
		o.Mutate.Files(p)
	}
	p.Manifest = manifestFor(k, o.Arch, p.Files)
	if o.Mutate.Manifest != nil {
		o.Mutate.Manifest(p.Manifest)
	}
	dir := t.TempDir()
	l, err := oci.Create(dir)
	must(t, err)
	indexDesc := writeArtifact(t, l, o.Arch, p)
	if !o.Mutate.Unsigned {
		var d [sha256.Size]byte
		raw, _ := hex.DecodeString(indexDesc.Digest.Encoded())
		copy(d[:], raw)
		var bundle []byte
		if o.Mutate.SignArtifact != nil {
			bundle = o.Mutate.SignArtifact(k, d)
		} else {
			bundle = k.Cosign.DSSEBundle(t, "sneakers-os", d)
		}
		AttachSignature(t, l, indexDesc, bundle)
	}
	if o.Mutate.After != nil {
		o.Mutate.After(t, l)
	}
	return dir, k.Pins()
}

func baseFiles(t testing.TB, k Keys, arch string) map[string][]byte {
	rel := []byte("apiVersion: sneakers-pam/v1alpha1\nkind: Release\nmetadata:\n  version: " + Version + "\n")
	files := map[string][]byte{
		verify.FileRelease:    rel,
		verify.FileReleaseSig: k.Cosign.BlobBundle(t, rel),
		rootName():            random(t, 64<<10),
	}
	if arch == "amd64" {
		files[ukiName()] = random(t, 16<<10)
		files["systemd-bootx64.efi"] = random(t, 8<<10)
		for _, name := range verify.SecureBootFiles {
			files[verify.SecureBootKeyPrefix+name] = random(t, 512)
		}
	} else {
		files[arm64Name()] = random(t, 16<<10)
	}
	return files
}

func ukiName() string   { return "sneakers-" + Version + ".efi" }
func rootName() string  { return "root-" + Version + ".img" }
func arm64Name() string { return "boot-arm64-" + Version + ".tar" }

func manifestFor(k Keys, arch string, files map[string][]byte) *verify.Manifest {
	sum := func(name string) string {
		s := sha256.Sum256(files[name])
		return hex.EncodeToString(s[:])
	}
	m := &verify.Manifest{
		APIVersion: verify.APIVersion,
		Kind:       verify.Kind,
		Metadata:   verify.Metadata{Version: Version, Channel: release.ChannelLab},
		Spec: verify.Spec{
			KitMin:  Version,
			Release: verify.ReleaseRef{Digest: "sha256:" + sum(verify.FileRelease)},
			Root: verify.Root{File: rootName(), SHA256: sum(rootName()), Verity: verify.Verity{
				RootHash: hex.EncodeToString(make([]byte, 32)), HashOffset: 4096, Algorithm: "sha256",
			}},
			Arch: arch,
		},
	}
	if arch == "amd64" {
		fp := k.Pins().Fingerprints()
		m.Spec.Protection = "full"
		m.Spec.Boot.UKI = &verify.UKI{File: ukiName(), SHA256: sum(ukiName()), SBAT: 1}
		m.Spec.Boot.Loader = &verify.Loader{File: "systemd-bootx64.efi", SHA256: sum("systemd-bootx64.efi"), Systemd: "lab"}
		sb := &verify.SecureBoot{Files: map[string]string{}}
		sb.PK.SHA256Fingerprint, sb.KEK.SHA256Fingerprint, sb.DB.SHA256Fingerprint = fp.PK, fp.KEK, fp.DB
		for _, name := range verify.SecureBootFiles {
			sb.Files[name] = sum(verify.SecureBootKeyPrefix + name)
		}
		m.Spec.SecureBoot = sb
	} else {
		m.Spec.Protection = "reduced"
		m.Spec.Boot.Arm64 = &verify.Arm64Boot{File: arm64Name(), SHA256: sum(arm64Name()), Files: map[string]string{"Image": sum(arm64Name())}}
	}
	return m
}

func writeArtifact(t testing.TB, l *oci.Layout, arch string, p *Parts) ocispec.Descriptor {
	t.Helper()
	appliance, err := yaml.Marshal(p.Manifest)
	must(t, err)
	layers := []ocispec.Descriptor{layer(t, l, verify.MediaTypeManifestFile, verify.FileAppliance, appliance)}
	for _, name := range sortedNames(p.Files) {
		layers = append(layers, layer(t, l, verify.MediaTypeFile, name, p.Files[name]))
	}
	cfg, err := l.WriteBlob(ocispec.MediaTypeEmptyJSON, ocispec.DescriptorEmptyJSON.Data)
	must(t, err)
	man, err := l.WriteJSON(ocispec.MediaTypeImageManifest, ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: verify.ArtifactType,
		Config:       cfg,
		Layers:       layers,
	})
	must(t, err)
	man.Platform = &ocispec.Platform{OS: "linux", Architecture: arch}
	idx, err := l.WriteJSON(ocispec.MediaTypeImageIndex, ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{man},
	})
	must(t, err)
	idx.Annotations = map[string]string{ocispec.AnnotationRefName: Version}
	top, err := l.Index()
	must(t, err)
	top.Manifests = append(top.Manifests, idx)
	must(t, l.WriteIndex(top))
	return idx
}

// AttachSignature writes bundle as a Sigstore referrer of subject.
func AttachSignature(t testing.TB, l *oci.Layout, subject ocispec.Descriptor, bundle []byte) {
	t.Helper()
	b, err := l.WriteBlob(verify.SignatureArtifactType, bundle)
	must(t, err)
	cfg, err := l.WriteBlob(ocispec.MediaTypeEmptyJSON, ocispec.DescriptorEmptyJSON.Data)
	must(t, err)
	subj := ocispec.Descriptor{MediaType: subject.MediaType, Digest: subject.Digest, Size: subject.Size}
	_, err = l.WriteJSON(ocispec.MediaTypeImageManifest, ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: verify.SignatureArtifactType,
		Config:       cfg,
		Layers:       []ocispec.Descriptor{b},
		Subject:      &subj,
	})
	must(t, err)
}

func layer(t testing.TB, l *oci.Layout, mediaType, title string, b []byte) ocispec.Descriptor {
	d, err := l.WriteBlob(mediaType, b)
	must(t, err)
	d.Annotations = map[string]string{verify.TitleAnnotation: title}
	return d
}

// BlobOf returns the path of the blob holding the file named title in the
// layout's one architecture manifest.
func BlobOf(t testing.TB, l *oci.Layout, title string) string {
	t.Helper()
	for _, man := range manifests(t, l) {
		for _, layer := range man.Layers {
			if layer.Annotations[verify.TitleAnnotation] == title {
				p, err := l.BlobPath(layer.Digest)
				must(t, err)
				return p
			}
		}
	}
	t.Fatalf("no layer %s", title)
	return ""
}

func manifests(t testing.TB, l *oci.Layout) []ocispec.Manifest {
	top, err := l.Index()
	must(t, err)
	var out []ocispec.Manifest
	for _, d := range top.Manifests {
		idx, err := l.ReadImageIndex(d)
		if err != nil {
			continue
		}
		for _, md := range idx.Manifests {
			m, err := l.ReadManifest(md)
			must(t, err)
			out = append(out, m)
		}
	}
	return out
}

func sortedNames(m map[string][]byte) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func random(t testing.TB, n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	must(t, err)
	return b
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// The mutations of spec 1 Section 6 that steps 1 to 5 refuse.

// DropSignature leaves the artifact unsigned.
var DropSignature = Mutation{Unsigned: true}

// ResignWithRogueCosign signs the artifact with a key the kit doesn't pin.
var ResignWithRogueCosign = Mutation{SignArtifact: func(k Keys, d [sha256.Size]byte) []byte {
	return k.RogueCosign.DSSEBundle(&noFail{}, "sneakers-os", d)
}}

// DropReleaseSignature ships release.yaml without its signature.
var DropReleaseSignature = Mutation{Files: func(p *Parts) { delete(p.Files, verify.FileReleaseSig) }}

// ResignRelease signs release.yaml with a key the kit doesn't pin.
var ResignRelease = Mutation{Files: func(p *Parts) {
	p.Files[verify.FileReleaseSig] = p.Keys.RogueCosign.BlobBundle(&noFail{}, p.Files[verify.FileRelease])
}}

// SwapLayer replaces the content of the named file ("root", "uki" or a file
// name) in the finished layout.
func SwapLayer(which string) Mutation {
	return Mutation{After: func(t testing.TB, l *oci.Layout) {
		name := map[string]string{"root": rootName(), "uki": ukiName()}[which]
		if name == "" {
			name = which
		}
		must(t, os.WriteFile(BlobOf(t, l, name), random(t, 64<<10), 0o600))
	}}
}

// LayerDigestEdit rewrites appliance.yaml's root digest before signing, so
// the signature holds but the root no longer matches.
var LayerDigestEdit = Mutation{Manifest: func(m *verify.Manifest) {
	m.Spec.Root.SHA256 = hex.EncodeToString(make([]byte, 32))
}}

// ExtraFile adds a layer appliance.yaml doesn't list, before signing.
var ExtraFile = Mutation{Files: func(p *Parts) { p.Files["extra.bin"] = []byte("extra") }}

// Lab against production: the fixture's pins say production.
func ProductionPins(p release.Pins) release.Pins {
	p.Channel = release.ChannelProduction
	return p
}

// noFail is a testing.TB for the package-level mutations, whose helpers
// never fail with in-memory keys.
type noFail struct{ testing.TB }

func (noFail) Helper()               {}
func (noFail) Fatal(args ...any)     { panic(args) }
func (noFail) Fatalf(string, ...any) { panic("fixture") }
