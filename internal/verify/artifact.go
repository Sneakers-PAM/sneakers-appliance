// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package verify

// The sneakers-os artifact (spec 1 Section 2.1) as an OCI image index: one
// image manifest per architecture, each carrying the release files as
// layers named by their title annotation, and a Sigstore bundle attached to
// the index as a referrer. docs/artifact.md describes it.
const (
	// ArtifactType is the artifactType of each per-architecture manifest.
	ArtifactType = "application/vnd.sneakers-pam.os.v1"
	// MediaTypeManifestFile is the media type of the appliance.yaml layer.
	MediaTypeManifestFile = "application/vnd.sneakers-pam.appliance.v1+yaml"
	// MediaTypeFile is the media type of every other release file.
	MediaTypeFile = "application/vnd.sneakers-pam.file.v1"
	// SignatureArtifactType is the artifactType of the signature referrer.
	SignatureArtifactType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	// TitleAnnotation names a layer's file.
	TitleAnnotation = "org.opencontainers.image.title"
)

// The fixed file names in every per-architecture manifest.
const (
	FileAppliance       = "appliance.yaml"
	FileRelease         = "release.yaml"
	FileReleaseSig      = "release.yaml.sigstore.json"
	SecureBootKeyPrefix = "keys/"
)

// ExpectedFiles lists every file m says the manifest carries, besides
// appliance.yaml itself, with its SHA-256 (hex). release.yaml's digest comes
// from spec.release.digest; its signature has none in the manifest.
func (m *Manifest) ExpectedFiles() map[string]string {
	files := map[string]string{
		FileRelease:      trimSHA(m.Spec.Release.Digest),
		FileReleaseSig:   "",
		m.Spec.Root.File: m.Spec.Root.SHA256,
	}
	if b := m.Spec.Boot.UKI; b != nil {
		files[b.File] = b.SHA256
	}
	if b := m.Spec.Boot.Loader; b != nil {
		files[b.File] = b.SHA256
	}
	if b := m.Spec.Boot.Arm64; b != nil {
		files[b.File] = b.SHA256
	}
	if sb := m.Spec.SecureBoot; sb != nil {
		for name, sum := range sb.Files {
			files[SecureBootKeyPrefix+name] = sum
		}
	}
	return files
}

func trimSHA(d string) string {
	const p = "sha256:"
	if len(d) > len(p) && d[:len(p)] == p {
		return d[len(p):]
	}
	return d
}
