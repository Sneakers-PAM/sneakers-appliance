// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
)

func mustParse(t *testing.T, path string) *verify.Manifest {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := verify.ParseManifest(b)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return m
}

func pins(t *testing.T, channel string) release.Pins {
	t.Helper()
	return release.Pins{
		Channel:       channel,
		ReleaseKeyPEM: testpki.ECDSA(t).PublicPEM,
		DBCertPEM:     testpki.SelfSigned(t, "db").PEM,
		PKCertPEM:     testpki.SelfSigned(t, "PK").PEM,
		KEKCertPEM:    testpki.SelfSigned(t, "KEK").PEM,
	}
}

func labPins(t *testing.T) release.Pins { return pins(t, release.ChannelLab) }

// productionPinsFor returns production pins and rewrites m's fingerprints to
// match them.
func productionPinsFor(t *testing.T, m *verify.Manifest) release.Pins {
	t.Helper()
	p := pins(t, release.ChannelProduction)
	if m.Spec.SecureBoot != nil {
		fp := p.Fingerprints()
		m.Spec.SecureBoot.PK.SHA256Fingerprint = fp.PK
		m.Spec.SecureBoot.KEK.SHA256Fingerprint = fp.KEK
		m.Spec.SecureBoot.DB.SHA256Fingerprint = fp.DB
	}
	return p
}

func TestManifestChannelMismatch(t *testing.T) {
	m := mustParse(t, "testdata/appliance-amd64.yaml") // channel: production
	err := m.CheckAgainst(labPins(t), "0.1.0")
	if !codes.Is(err, codes.KitChannel) {
		t.Fatalf("want KIT_CHANNEL, got %v", err)
	}
}

func TestManifestLabAgainstProductionKit(t *testing.T) {
	m := mustParse(t, "testdata/appliance-amd64.yaml")
	m.Metadata.Channel = release.ChannelLab
	err := m.CheckAgainst(pins(t, release.ChannelProduction), "0.2.0")
	if !codes.Is(err, codes.KitChannel) {
		t.Fatalf("want KIT_CHANNEL, got %v", err)
	}
}

func TestManifestKitTooOld(t *testing.T) {
	m := mustParse(t, "testdata/appliance-amd64.yaml") // kitMin: 0.2.0
	err := m.CheckAgainst(productionPinsFor(t, m), "0.1.0")
	if !codes.Is(err, codes.KitKitTooOld) {
		t.Fatalf("want KIT_KIT_TOO_OLD, got %v", err)
	}
}

func TestManifestKitVersionComparesAsSemver(t *testing.T) {
	m := mustParse(t, "testdata/appliance-amd64.yaml")
	p := productionPinsFor(t, m)
	for kit, ok := range map[string]bool{"0.2.0": true, "0.10.0": true, "0.2.0-rc.1": false, "0.1.9": false} {
		err := m.CheckAgainst(p, kit)
		if (err == nil) != ok {
			t.Errorf("kit %s: got %v", kit, err)
		}
	}
}

func TestManifestWrongFingerprint(t *testing.T) {
	m := mustParse(t, "testdata/appliance-amd64.yaml")
	p := productionPinsFor(t, m)
	m.Spec.SecureBoot.DB.SHA256Fingerprint = strings.Repeat("0", 64)
	if err := m.CheckAgainst(p, "0.2.0"); !codes.Is(err, codes.KitWrongSigner) {
		t.Fatalf("want KIT_WRONG_SIGNER, got %v", err)
	}
}

func TestManifestAcceptsMatchingPins(t *testing.T) {
	m := mustParse(t, "testdata/appliance-amd64.yaml")
	if err := m.CheckAgainst(productionPinsFor(t, m), "0.2.0"); err != nil {
		t.Fatal(err)
	}
}

func TestArm64ManifestHasNoSecureBootBlock(t *testing.T) {
	m := mustParse(t, "testdata/appliance-arm64.yaml")
	if m.Spec.SecureBoot != nil || m.Spec.Protection != "reduced" {
		t.Fatal("arm64 must be reduced, no secureBoot")
	}
	if m.Spec.Boot.Arm64 == nil || m.Spec.Boot.UKI != nil {
		t.Fatal("arm64 carries boot.arm64 only")
	}
	if err := m.CheckAgainst(productionPinsFor(t, m), "0.1.0"); err != nil {
		t.Fatal(err)
	}
}

func TestManifestRoundTrips(t *testing.T) {
	for _, f := range []string{"testdata/appliance-amd64.yaml", "testdata/appliance-arm64.yaml"} {
		m := mustParse(t, f)
		out, err := yaml.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		again, err := verify.ParseManifest(out)
		if err != nil {
			t.Fatalf("%s: re-parse: %v\n%s", f, err, out)
		}
		if !reflect.DeepEqual(m, again) {
			t.Fatalf("%s: round trip changed the manifest:\n%s", f, out)
		}
	}
}

func TestManifestStructuralRefusals(t *testing.T) {
	base, err := os.ReadFile("testdata/appliance-amd64.yaml")
	if err != nil {
		t.Fatal(err)
	}
	arm, err := os.ReadFile("testdata/appliance-arm64.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"unknown field":         strings.Replace(string(base), "  kitMin: 0.2.0", "  kitMin: 0.2.0\n  extra: 1", 1),
		"wrong kind":            strings.Replace(string(base), "kind: Appliance", "kind: Other", 1),
		"wrong apiVersion":      strings.Replace(string(base), "sneakers-pam/v1alpha1", "sneakers-pam/v1", 1),
		"bad channel":           strings.Replace(string(base), "channel: production", "channel: beta", 1),
		"bad version":           strings.Replace(string(base), "version: 0.2.0", "version: two", 1),
		"bad digest":            strings.Replace(string(base), "sha256: 2222", "sha256: zz22", 1),
		"amd64 reduced":         strings.Replace(string(base), "protection: full", "protection: reduced", 1),
		"amd64 no secureBoot":   string(base[:strings.Index(string(base), "  secureBoot:")]) + "  arch: amd64\n  protection: full\n",
		"arm64 full":            strings.Replace(string(arm), "protection: reduced", "protection: full", 1),
		"unknown arch":          strings.Replace(string(arm), "arch: arm64", "arch: riscv64", 1),
		"verity algorithm":      strings.Replace(string(base), "algorithm: sha256", "algorithm: sha1", 1),
		"upgradeFrom above ver": strings.Replace(string(base), "upgradeFrom: 0.1.0", "upgradeFrom: 0.3.0", 1),
		"missing sb file":       strings.Replace(string(base), "      dbx.esl: cdcd", "      dbx.zzz: cdcd", 1),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := verify.ParseManifest([]byte(doc)); !codes.Is(err, codes.KitManifestInvalid) {
				t.Fatalf("want KIT_MANIFEST_INVALID, got %v", err)
			}
		})
	}
}
