// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package verify is the verification chain of spec 1 Section 2.3, shared by
// sneakers-kit and the box's Image.Stage.
package verify

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
)

// The manifest's fixed header.
const (
	APIVersion = "sneakers-pam/v1alpha1"
	Kind       = "Appliance"
)

// Manifest is appliance.yaml (spec 1 Section 4.1), one per architecture.
type Manifest struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

// Metadata names the release.
type Metadata struct {
	Version string `yaml:"version"`
	Channel string `yaml:"channel"`
}

// Spec is the body of the manifest.
type Spec struct {
	KitMin     string      `yaml:"kitMin"`
	Release    ReleaseRef  `yaml:"release"`
	Boot       Boot        `yaml:"boot"`
	Root       Root        `yaml:"root"`
	SecureBoot *SecureBoot `yaml:"secureBoot,omitempty"`
	// UpgradeFrom is the oldest version that may upgrade straight to this one
	// (plan 5); empty means any.
	UpgradeFrom string `yaml:"upgradeFrom,omitempty"`
	// ManualOnly keeps this release out of automatic updates (plan 5).
	ManualOnly bool   `yaml:"manualOnly,omitempty"`
	Arch       string `yaml:"arch"`
	Protection string `yaml:"protection"`
}

// ReleaseRef pins release.yaml by digest.
type ReleaseRef struct {
	Digest string `yaml:"digest"`
}

// Boot holds the amd64 UKI and loader, or the arm64 boot tarball.
type Boot struct {
	UKI    *UKI       `yaml:"uki,omitempty"`
	Loader *Loader    `yaml:"loader,omitempty"`
	Arm64  *Arm64Boot `yaml:"arm64,omitempty"`
}

// UKI is the signed unified kernel image.
type UKI struct {
	File   string `yaml:"file"`
	SHA256 string `yaml:"sha256"`
	SBAT   int    `yaml:"sbat"`
}

// Loader is the signed systemd-boot.
type Loader struct {
	File    string `yaml:"file"`
	SHA256  string `yaml:"sha256"`
	Systemd string `yaml:"systemd"`
}

// Arm64Boot is boot-arm64-<version>.tar and the digest of every file in it.
type Arm64Boot struct {
	File   string            `yaml:"file"`
	SHA256 string            `yaml:"sha256"`
	Files  map[string]string `yaml:"files"`
}

// Root is the SquashFS root with its appended verity tree.
type Root struct {
	File   string `yaml:"file"`
	SHA256 string `yaml:"sha256"`
	Verity Verity `yaml:"verity"`
}

// Verity describes the dm-verity tree appended to the root image.
type Verity struct {
	RootHash   string `yaml:"roothash"`
	HashOffset int64  `yaml:"hashOffset"`
	Algorithm  string `yaml:"algorithm"`
}

// SecureBoot is the enrolment material (amd64 only).
type SecureBoot struct {
	PK    CertRef           `yaml:"pk"`
	KEK   CertRef           `yaml:"kek"`
	DB    CertRef           `yaml:"db"`
	Files map[string]string `yaml:"files"`
}

// CertRef names a certificate by fingerprint.
type CertRef struct {
	SHA256Fingerprint string `yaml:"sha256Fingerprint"`
}

// SecureBootFiles are the enrolment files every amd64 manifest lists.
var SecureBootFiles = []string{"PK.auth", "KEK.auth", "db.auth", "PK.esl", "KEK.esl", "db.esl", "dbx.esl"}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ParseManifest decodes appliance.yaml strictly and checks its structure.
func ParseManifest(b []byte) (*Manifest, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, codes.New(codes.KitManifestInvalid, "appliance.yaml doesn't parse: %v", err)
	}
	if err := m.validate(); err != nil {
		return nil, codes.New(codes.KitManifestInvalid, "appliance.yaml: %v", err)
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	if m.APIVersion != APIVersion || m.Kind != Kind {
		return fmt.Errorf("apiVersion and kind must be %s %s, not %s %s", APIVersion, Kind, m.APIVersion, m.Kind)
	}
	if !validVersion(m.Metadata.Version) {
		return fmt.Errorf("metadata.version %q isn't a semantic version", m.Metadata.Version)
	}
	switch m.Metadata.Channel {
	case release.ChannelProduction, release.ChannelLab:
	default:
		return fmt.Errorf("metadata.channel %q must be production or lab", m.Metadata.Channel)
	}
	s := m.Spec
	if !validVersion(s.KitMin) {
		return fmt.Errorf("spec.kitMin %q isn't a semantic version", s.KitMin)
	}
	if s.UpgradeFrom != "" {
		if !validVersion(s.UpgradeFrom) {
			return fmt.Errorf("spec.upgradeFrom %q isn't a semantic version", s.UpgradeFrom)
		}
		if semver.Compare("v"+s.UpgradeFrom, "v"+m.Metadata.Version) > 0 {
			return fmt.Errorf("spec.upgradeFrom %s is above the version %s", s.UpgradeFrom, m.Metadata.Version)
		}
	}
	if err := checkHex("spec.release.digest", strings.TrimPrefix(s.Release.Digest, "sha256:")); err != nil || !strings.HasPrefix(s.Release.Digest, "sha256:") {
		return fmt.Errorf("spec.release.digest %q must be sha256:<64 hex>", s.Release.Digest)
	}
	if err := fileRef("spec.root", s.Root.File, s.Root.SHA256); err != nil {
		return err
	}
	if err := checkHex("spec.root.verity.roothash", s.Root.Verity.RootHash); err != nil {
		return err
	}
	if s.Root.Verity.Algorithm != "sha256" {
		return fmt.Errorf("spec.root.verity.algorithm %q must be sha256", s.Root.Verity.Algorithm)
	}
	if s.Root.Verity.HashOffset <= 0 || s.Root.Verity.HashOffset%4096 != 0 {
		return fmt.Errorf("spec.root.verity.hashOffset %d must be a positive multiple of 4096", s.Root.Verity.HashOffset)
	}
	switch s.Arch {
	case "amd64":
		return m.validateAmd64()
	case "arm64":
		return m.validateArm64()
	default:
		return fmt.Errorf("spec.arch %q must be amd64 or arm64", s.Arch)
	}
}

func (m *Manifest) validateAmd64() error {
	s := m.Spec
	if s.Protection != "full" {
		return fmt.Errorf("an amd64 manifest has protection full, not %q", s.Protection)
	}
	if s.Boot.Arm64 != nil || s.Boot.UKI == nil || s.Boot.Loader == nil || s.SecureBoot == nil {
		return fmt.Errorf("an amd64 manifest has boot.uki, boot.loader and secureBoot, and no boot.arm64")
	}
	if err := fileRef("spec.boot.uki", s.Boot.UKI.File, s.Boot.UKI.SHA256); err != nil {
		return err
	}
	if s.Boot.UKI.SBAT < 1 {
		return fmt.Errorf("spec.boot.uki.sbat must be 1 or more")
	}
	if err := fileRef("spec.boot.loader", s.Boot.Loader.File, s.Boot.Loader.SHA256); err != nil {
		return err
	}
	sb := s.SecureBoot
	for name, fp := range map[string]string{"pk": sb.PK.SHA256Fingerprint, "kek": sb.KEK.SHA256Fingerprint, "db": sb.DB.SHA256Fingerprint} {
		if err := checkHex("spec.secureBoot."+name+".sha256Fingerprint", fp); err != nil {
			return err
		}
	}
	return exactFiles("spec.secureBoot.files", sb.Files, SecureBootFiles)
}

func (m *Manifest) validateArm64() error {
	s := m.Spec
	if s.Protection != "reduced" {
		return fmt.Errorf("an arm64 manifest has protection reduced, not %q", s.Protection)
	}
	if s.Boot.Arm64 == nil || s.Boot.UKI != nil || s.Boot.Loader != nil || s.SecureBoot != nil {
		return fmt.Errorf("an arm64 manifest has boot.arm64 only, and no secureBoot")
	}
	if err := fileRef("spec.boot.arm64", s.Boot.Arm64.File, s.Boot.Arm64.SHA256); err != nil {
		return err
	}
	if len(s.Boot.Arm64.Files) == 0 {
		return fmt.Errorf("spec.boot.arm64.files lists no files")
	}
	for name, d := range s.Boot.Arm64.Files {
		if err := checkHex("spec.boot.arm64.files."+name, d); err != nil {
			return err
		}
	}
	return nil
}

func exactFiles(field string, got map[string]string, want []string) error {
	if len(got) != len(want) {
		return fmt.Errorf("%s must list exactly %s", field, strings.Join(want, ", "))
	}
	for _, name := range want {
		d, ok := got[name]
		if !ok {
			return fmt.Errorf("%s must list exactly %s", field, strings.Join(want, ", "))
		}
		if err := checkHex(field+"."+name, d); err != nil {
			return err
		}
	}
	return nil
}

func fileRef(field, file, sum string) error {
	if file == "" || strings.ContainsAny(file, "/\\") || file == "." || file == ".." {
		return fmt.Errorf("%s.file %q must be a plain file name", field, file)
	}
	return checkHex(field+".sha256", sum)
}

func checkHex(field, d string) error {
	if !hex64.MatchString(d) {
		return fmt.Errorf("%s %q must be 64 lowercase hex characters", field, d)
	}
	return nil
}

func validVersion(v string) bool {
	return v != "" && !strings.HasPrefix(v, "v") && semver.IsValid("v"+v)
}

// CheckAgainst runs step 3 of the chain: the manifest's channel must be the
// kit's, kitMin must be at most kitVersion, and the certificate fingerprints
// must be the pinned ones.
func (m *Manifest) CheckAgainst(p release.Pins, kitVersion string) error {
	if m.Metadata.Channel != p.Channel {
		return codes.New(codes.KitChannel, "appliance.yaml is a %s release; this kit is %s", m.Metadata.Channel, p.Channel)
	}
	if !validVersion(kitVersion) || semver.Compare("v"+kitVersion, "v"+m.Spec.KitMin) < 0 {
		return codes.New(codes.KitKitTooOld, "appliance.yaml needs kit %s or later; this kit is %s", m.Spec.KitMin, kitVersion)
	}
	if sb := m.Spec.SecureBoot; sb != nil {
		fp := p.Fingerprints()
		var wrong []string
		for name, pair := range map[string][2]string{
			"PK":  {sb.PK.SHA256Fingerprint, fp.PK},
			"KEK": {sb.KEK.SHA256Fingerprint, fp.KEK},
			"db":  {sb.DB.SHA256Fingerprint, fp.DB},
		} {
			if pair[0] != pair[1] {
				wrong = append(wrong, name)
			}
		}
		if len(wrong) > 0 {
			sort.Strings(wrong)
			return codes.New(codes.KitWrongSigner, "appliance.yaml names %s certificates other than the ones this kit pins", strings.Join(wrong, ", "))
		}
	}
	return nil
}
