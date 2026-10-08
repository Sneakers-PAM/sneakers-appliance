// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package artifact assembles the sneakers-os artifact (docs/artifact.md):
// appliance.yaml from the release files, and the OCI layout that carries
// them. It signs nothing; the signature is attached afterwards, by the
// release workflow's sign job or by a lab build with its throwaway key.
package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"

	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/oci"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
)

// File is one release file, from disk (Path) or memory (Data).
type File struct {
	Path string
	Data []byte
}

func (f File) open() (io.ReadCloser, error) {
	if f.Path != "" {
		return os.Open(f.Path) // #nosec G304 -- a release file the build named
	}
	return io.NopCloser(bytes.NewReader(f.Data)), nil
}

func (f File) digest() (string, int64, error) {
	r, err := f.open()
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = r.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, r)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// Input is everything one architecture's manifest is made from.
type Input struct {
	Arch, Version, Channel, KitMin string
	// Release is release.yaml and ReleaseSig its signature bundle.
	Release, ReleaseSig File
	Root                File
	RootHash            string
	HashOffset          int64
	// amd64.
	UKI, Loader File
	Systemd     string
	SBAT        int
	// Keys are the enrolment files by name (PK.auth ... dbx.esl).
	Keys         map[string]File
	Fingerprints release.Fingerprints
	// arm64.
	BootTarball File
	BootFiles   map[string]string // name -> SHA-256 of each file in the tarball
	// UpgradeFrom and ManualOnly are plan 5's fields.
	UpgradeFrom string
	ManualOnly  bool
	// Extra are further layers by title (tests that check the chain
	// refuses them).
	Extra map[string]File
}

func (f File) zero() bool { return f.Path == "" && f.Data == nil }

// Names of the files in the artifact.
func (in Input) rootName() string  { return "root-" + in.Version + ".img" }
func (in Input) ukiName() string   { return "sneakers-" + in.Version + ".efi" }
func (in Input) arm64Name() string { return "boot-arm64-" + in.Version + ".tar" }

const loaderName = "systemd-bootx64.efi"

// files lists every layer by title.
func (in Input) files() map[string]File {
	files := map[string]File{verify.FileRelease: in.Release, verify.FileReleaseSig: in.ReleaseSig, in.rootName(): in.Root}
	if in.Arch == "amd64" {
		files[in.ukiName()] = in.UKI
		files[loaderName] = in.Loader
		for name, f := range in.Keys {
			files[verify.SecureBootKeyPrefix+name] = f
		}
	} else {
		files[in.arm64Name()] = in.BootTarball
	}
	for name, f := range in.Extra {
		files[name] = f
	}
	for name, f := range files {
		if f.zero() {
			delete(files, name)
		}
	}
	return files
}

// DefaultKitMin is the kitMin a release gets unless it names one: the
// lowest semantic version, so any kit or init that reads this manifest
// format accepts it. Raise it only when a release needs a newer verifier.
const DefaultKitMin = "0.0.0-0"

// Manifest builds appliance.yaml for in, given each file's SHA-256.
func (in Input) Manifest(sums map[string]string) *verify.Manifest {
	kitMin := in.KitMin
	if kitMin == "" {
		kitMin = DefaultKitMin
	}
	m := &verify.Manifest{
		APIVersion: verify.APIVersion,
		Kind:       verify.Kind,
		Metadata:   verify.Metadata{Version: in.Version, Channel: in.Channel},
		Spec: verify.Spec{
			KitMin:  kitMin,
			Release: verify.ReleaseRef{Digest: "sha256:" + sums[verify.FileRelease]},
			Root: verify.Root{File: in.rootName(), SHA256: sums[in.rootName()], Verity: verify.Verity{
				RootHash: in.RootHash, HashOffset: in.HashOffset, Algorithm: "sha256",
			}},
			UpgradeFrom: in.UpgradeFrom,
			ManualOnly:  in.ManualOnly,
			Arch:        in.Arch,
		},
	}
	if in.Arch == "amd64" {
		m.Spec.Protection = "full"
		sbat := in.SBAT
		if sbat == 0 {
			sbat = 1
		}
		m.Spec.Boot.UKI = &verify.UKI{File: in.ukiName(), SHA256: sums[in.ukiName()], SBAT: sbat}
		m.Spec.Boot.Loader = &verify.Loader{File: loaderName, SHA256: sums[loaderName], Systemd: in.Systemd}
		sb := &verify.SecureBoot{Files: map[string]string{}}
		sb.PK.SHA256Fingerprint, sb.KEK.SHA256Fingerprint, sb.DB.SHA256Fingerprint = in.Fingerprints.PK, in.Fingerprints.KEK, in.Fingerprints.DB
		for name := range in.Keys {
			sb.Files[name] = sums[verify.SecureBootKeyPrefix+name]
		}
		m.Spec.SecureBoot = sb
	} else {
		m.Spec.Protection = "reduced"
		m.Spec.Boot.Arm64 = &verify.Arm64Boot{File: in.arm64Name(), SHA256: sums[in.arm64Name()], Files: in.BootFiles}
	}
	return m
}

// Write writes in as an artifact in a new layout at dir, with the manifest
// edited by edit when it's set, and returns the index's descriptor. The
// artifact is unsigned.
func Write(dir string, in Input, edit func(*verify.Manifest)) (ocispec.Descriptor, error) {
	l, err := oci.Create(dir)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	files := in.files()
	sums := map[string]string{}
	sizes := map[string]int64{}
	for name, f := range files {
		s, n, err := f.digest()
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("artifact: %s: %w", name, err)
		}
		sums[name], sizes[name] = s, n
	}
	m := in.Manifest(sums)
	if edit != nil {
		edit(m)
	}
	appliance, err := yaml.Marshal(m)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	desc, err := l.WriteBlob(verify.MediaTypeManifestFile, appliance)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	desc.Annotations = map[string]string{verify.TitleAnnotation: verify.FileAppliance}
	layers := []ocispec.Descriptor{desc}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		d := ocispec.Descriptor{MediaType: verify.MediaTypeFile, Digest: digest.NewDigestFromEncoded(digest.SHA256, sums[name]), Size: sizes[name],
			Annotations: map[string]string{verify.TitleAnnotation: name}}
		r, err := files[name].open()
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		err = l.WriteBlobFrom(d, r)
		_ = r.Close()
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("artifact: %s: %w", name, err)
		}
		layers = append(layers, d)
	}
	cfg, err := l.WriteBlob(ocispec.MediaTypeEmptyJSON, ocispec.DescriptorEmptyJSON.Data)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	man, err := l.WriteJSON(ocispec.MediaTypeImageManifest, ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest,
		ArtifactType: verify.ArtifactType, Config: cfg, Layers: layers,
	})
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	man.Platform = &ocispec.Platform{OS: "linux", Architecture: in.Arch}
	idx, err := l.WriteJSON(ocispec.MediaTypeImageIndex, ocispec.Index{
		Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: []ocispec.Descriptor{man},
	})
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	idx.Annotations = map[string]string{ocispec.AnnotationRefName: in.Version}
	top, err := l.Index()
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	top.Manifests = append(top.Manifests, idx)
	return idx, l.WriteIndex(top)
}

// AttachSignature writes bundle as the Sigstore referrer of subject and
// lists it in index.json.
func AttachSignature(l *oci.Layout, subject ocispec.Descriptor, bundle []byte) error {
	b, err := l.WriteBlob(verify.SignatureArtifactType, bundle)
	if err != nil {
		return err
	}
	cfg, err := l.WriteBlob(ocispec.MediaTypeEmptyJSON, ocispec.DescriptorEmptyJSON.Data)
	if err != nil {
		return err
	}
	subj := ocispec.Descriptor{MediaType: subject.MediaType, Digest: subject.Digest, Size: subject.Size}
	sig, err := l.WriteJSON(ocispec.MediaTypeImageManifest, ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest,
		ArtifactType: verify.SignatureArtifactType, Config: cfg, Layers: []ocispec.Descriptor{b}, Subject: &subj,
	})
	if err != nil {
		return err
	}
	sig.ArtifactType = verify.SignatureArtifactType
	top, err := l.Index()
	if err != nil {
		return err
	}
	top.Manifests = append(top.Manifests, sig)
	return l.WriteIndex(top)
}
