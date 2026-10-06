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
	"testing/fstest"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/artifact"
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
	Keys       Keys
	Arch       string
	Files      map[string][]byte
	RootHash   string
	HashOffset int64
	Manifest   *verify.Manifest
}

// Mutation breaks one thing about the fixture.
type Mutation struct {
	// Root edits the root tree before the root image is built.
	Root func(m fstest.MapFS)
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
	p := baseParts(t, k, o.Arch, o.Mutate.Root)
	if o.Mutate.Files != nil {
		o.Mutate.Files(p)
	}
	dir := t.TempDir()
	indexDesc, err := artifact.Write(dir, p.input(), func(m *verify.Manifest) {
		p.Manifest = m
		if o.Mutate.Manifest != nil {
			o.Mutate.Manifest(m)
		}
	})
	must(t, err)
	l, err := oci.Open(dir)
	must(t, err)
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
		must(t, artifact.AttachSignature(l, indexDesc, bundle))
	}
	if o.Mutate.After != nil {
		o.Mutate.After(t, l)
	}
	return dir, k.Pins()
}

// input maps the parts onto the artifact's input; files it doesn't know
// become extra layers.
func (p *Parts) input() artifact.Input {
	in := artifact.Input{Arch: p.Arch, Version: Version, Channel: release.ChannelLab, RootHash: p.RootHash, HashOffset: p.HashOffset,
		Systemd: "lab", Fingerprints: p.Keys.Pins().Fingerprints(), Keys: map[string]artifact.File{}, Extra: map[string]artifact.File{}}
	for name, b := range p.Files {
		f := artifact.File{Data: b}
		switch {
		case name == verify.FileRelease:
			in.Release = f
		case name == verify.FileReleaseSig:
			in.ReleaseSig = f
		case name == rootName():
			in.Root = f
		case name == ukiName():
			in.UKI = f
		case name == "systemd-bootx64.efi":
			in.Loader = f
		case name == arm64Name():
			in.BootTarball, in.BootFiles = f, tarDigests(b)
		case len(name) > len(verify.SecureBootKeyPrefix) && name[:len(verify.SecureBootKeyPrefix)] == verify.SecureBootKeyPrefix:
			in.Keys[name[len(verify.SecureBootKeyPrefix):]] = f
		default:
			in.Extra[name] = f
		}
	}
	return in
}

func ukiName() string   { return "sneakers-" + Version + ".efi" }
func rootName() string  { return "root-" + Version + ".img" }
func arm64Name() string { return "boot-arm64-" + Version + ".tar" }

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
