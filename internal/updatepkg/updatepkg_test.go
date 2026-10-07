// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package updatepkg_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// keySet is one channel's signing key and encryption key, made for this test.
type keySet struct {
	sign testpki.ECKey
	enc  *age.X25519Identity
}

func newKeySet(t *testing.T) keySet {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return keySet{sign: testpki.ECDSA(t), enc: id}
}

func fullHeader(channel string) updatepkg.Header {
	return updatepkg.Header{Version: "0.2.0", Arch: "amd64", Kind: updatepkg.KindFull, Channel: channel}
}

// build makes a .bin the way the release workflow does: encrypt, sign the
// header with the channel's release key, then seal.
func build(t *testing.T, ks keySet, h updatepkg.Header, payload []byte) []byte {
	t.Helper()
	var ct bytes.Buffer
	h, err := updatepkg.Encrypt(bytes.NewReader(payload), h, ks.enc.Recipient(), &ct)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := updatepkg.Seal(&out, hdr, ks.sign.BlobBundle(t, hdr), &ct); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func read(t *testing.T, b []byte) *updatepkg.Package {
	t.Helper()
	p, err := updatepkg.Read(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestARoundTripVerifiesAndDecrypts(t *testing.T) {
	ks := newKeySet(t)
	payload := []byte("the release, its images, charts and add-ons")
	p := read(t, build(t, ks, fullHeader(release.ChannelProduction), payload))
	if err := p.Verify(ks.sign.PublicPEM, release.ChannelProduction); err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if err := p.Decrypt(ks.enc, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("payload %q", got.String())
	}
	if p.Header.Version != "0.2.0" || p.Header.Name != updatepkg.Name || p.Header.Format != updatepkg.Format {
		t.Fatalf("header %+v", p.Header)
	}
}

func TestTheCiphertextHidesThePayload(t *testing.T) {
	ks := newKeySet(t)
	b := build(t, ks, fullHeader(release.ChannelLab), []byte("a plainly visible marker"))
	if bytes.Contains(b, []byte("plainly visible")) {
		t.Fatal("the payload is readable in the .bin")
	}
}

func TestDecryptRefusesBeforeVerify(t *testing.T) {
	ks := newKeySet(t)
	p := read(t, build(t, ks, fullHeader(release.ChannelLab), []byte("x")))
	if err := p.Decrypt(ks.enc, &bytes.Buffer{}); !codes.Is(err, codes.UpgradeSignature) {
		t.Fatalf("want UPGRADE_SIGNATURE before a verify, got %v", err)
	}
}

func TestAnotherSigningKeyIsRefused(t *testing.T) {
	ks, other := newKeySet(t), newKeySet(t)
	p := read(t, build(t, ks, fullHeader(release.ChannelProduction), []byte("x")))
	if err := p.Verify(other.sign.PublicPEM, release.ChannelProduction); !codes.Is(err, codes.UpgradeSignature) {
		t.Fatalf("want UPGRADE_SIGNATURE, got %v", err)
	}
}

func TestALabPackageNeverInstallsOnAProductionBox(t *testing.T) {
	lab, prod := newKeySet(t), newKeySet(t)
	b := build(t, lab, fullHeader(release.ChannelLab), []byte("x"))
	// Signed with the lab key: the production box's key refuses it, and the
	// refusal names the channel.
	if err := read(t, b).Verify(prod.sign.PublicPEM, release.ChannelProduction); !codes.Is(err, codes.UpgradeChannel) {
		t.Fatalf("want UPGRADE_CHANNEL, got %v", err)
	}
	// Even a box that somehow trusted the lab key refuses a lab channel.
	if err := read(t, b).Verify(lab.sign.PublicPEM, release.ChannelProduction); !codes.Is(err, codes.UpgradeChannel) {
		t.Fatalf("want UPGRADE_CHANNEL, got %v", err)
	}
}

func TestAnotherEncryptionKeyIsRefused(t *testing.T) {
	ks, other := newKeySet(t), newKeySet(t)
	p := read(t, build(t, ks, fullHeader(release.ChannelProduction), []byte("x")))
	if err := p.Verify(ks.sign.PublicPEM, release.ChannelProduction); err != nil {
		t.Fatal(err)
	}
	if err := p.Decrypt(other.enc, &bytes.Buffer{}); !codes.Is(err, codes.UpgradeDecrypt) {
		t.Fatalf("want UPGRADE_DECRYPT, got %v", err)
	}
}

func TestATamperedFileIsRefused(t *testing.T) {
	ks := newKeySet(t)
	good := build(t, ks, fullHeader(release.ChannelProduction), bytes.Repeat([]byte("p"), 4096))
	for name, mutate := range map[string]func([]byte){
		"ciphertext byte": func(b []byte) { b[len(b)-10] ^= 1 },
		"header byte":     func(b []byte) { b[bytes.Index(b, []byte(`"0.2.0"`))+1] = '9' },
	} {
		b := bytes.Clone(good)
		mutate(b)
		if err := read(t, b).Verify(ks.sign.PublicPEM, release.ChannelProduction); !codes.Is(err, codes.UpgradeSignature) {
			t.Errorf("%s: want UPGRADE_SIGNATURE, got %v", name, err)
		}
	}
	b := append(bytes.Clone(good), 'x')
	if err := read(t, b).Verify(ks.sign.PublicPEM, release.ChannelProduction); !codes.Is(err, codes.UpgradeSignature) {
		t.Errorf("trailing byte: want UPGRADE_SIGNATURE, got %v", err)
	}
}

func TestNotAPackage(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":     nil,
		"oci tar":   []byte("oci-layout\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
		"truncated": []byte(updatepkg.Magic + "\x00\x00\x10\x00{"),
	} {
		if _, err := updatepkg.Read(bytes.NewReader(b), int64(len(b))); !codes.Is(err, codes.UpgradeFormat) {
			t.Errorf("%s: want UPGRADE_FORMAT, got %v", name, err)
		}
	}
}

func TestHeaderRules(t *testing.T) {
	ks := newKeySet(t)
	for name, h := range map[string]updatepkg.Header{
		"no version":        {Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelLab},
		"bad arch":          {Version: "0.2.0", Arch: "riscv64", Kind: updatepkg.KindFull, Channel: release.ChannelLab},
		"bad channel":       {Version: "0.2.0", Arch: "amd64", Kind: updatepkg.KindFull, Channel: "dev"},
		"full with bases":   {Version: "0.2.0", Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelLab, Bases: []string{"0.1.0"}},
		"patch with none":   {Version: "0.2.0-p1", Arch: "amd64", Kind: updatepkg.KindPatch, Channel: release.ChannelLab},
		"unknown kind":      {Version: "0.2.0", Arch: "amd64", Kind: "delta", Channel: release.ChannelLab},
		"version with path": {Version: "../0.2.0", Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelLab},
	} {
		if _, err := updatepkg.Encrypt(strings.NewReader("x"), h, ks.enc.Recipient(), &bytes.Buffer{}); !codes.Is(err, codes.UpgradeFormat) {
			t.Errorf("%s: want UPGRADE_FORMAT, got %v", name, err)
		}
	}
}

func TestAPatchAppliesOnlyToItsBaseVersions(t *testing.T) {
	ks := newKeySet(t)
	h := updatepkg.Header{Version: "0.2.0-p1", Arch: "amd64", Kind: updatepkg.KindPatch, Channel: release.ChannelProduction, Bases: []string{"0.2.0"}}
	p := read(t, build(t, ks, h, []byte("one image")))
	if err := p.Verify(ks.sign.PublicPEM, release.ChannelProduction); err != nil {
		t.Fatal(err)
	}
	if err := p.Header.AppliesTo("0.2.0"); err != nil {
		t.Fatalf("on its base: %v", err)
	}
	for _, running := range []string{"0.1.0", "0.2.1", "0.2.0-p1"} {
		if err := p.Header.AppliesTo(running); !codes.Is(err, codes.UpgradePatchBase) {
			t.Errorf("on %s: want UPGRADE_PATCH_BASE, got %v", running, err)
		}
	}
	full := read(t, build(t, ks, fullHeader(release.ChannelProduction), []byte("x")))
	if err := full.Header.AppliesTo("0.1.0"); err != nil {
		t.Fatalf("a full version names no base: %v", err)
	}
}

func TestFileNames(t *testing.T) {
	if got := updatepkg.FileName(fullHeader(release.ChannelProduction)); got != "sneakers-appliance-0.2.0-amd64.bin" {
		t.Fatalf("production: %s", got)
	}
	if got := updatepkg.FileName(fullHeader(release.ChannelLab)); got != "sneakers-appliance-0.2.0-amd64-LAB.bin" {
		t.Fatalf("lab: %s", got)
	}
}

func TestTheDirectoryTarIsReproducibleAndUnpacks(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "blobs", "sha256"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"oci-layout": "{}", "index.json": "{}", "blobs/sha256/aa": "blob"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var a, b bytes.Buffer
	if err := updatepkg.TarDir(src, &a); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(src, "index.json"), timeZero, timeZero.AddDate(1, 0, 0)); err != nil {
		t.Fatal(err)
	}
	if err := updatepkg.TarDir(src, &b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("the tar depends on file times")
	}
	dst := t.TempDir()
	if err := updatepkg.Untar(&a, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "blobs", "sha256", "aa"))
	if err != nil || string(got) != "blob" {
		t.Fatalf("unpacked %q, %v", got, err)
	}
}

func TestUntarRefusesAPathOutsideTheDirectory(t *testing.T) {
	if err := updatepkg.Untar(bytes.NewReader(evilTar(t)), t.TempDir()); !codes.Is(err, codes.UpgradeFormat) {
		t.Fatalf("want UPGRADE_FORMAT, got %v", err)
	}
}

// A lab build's version carries its build number, git-describe style
// (0.0.0-lab.20261007d-g1a2b3c4): a hyphen inside a pre-release
// identifier is SemVer, and the package takes it. A version that's empty
// after the hyphen, or holds anything outside SemVer's characters, still
// isn't one.
func TestABuildNumberInTheVersion(t *testing.T) {
	ks := newKeySet(t)
	h := updatepkg.Header{Version: "0.0.0-lab.20261007d-g1a2b3c4", Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelLab}
	if _, err := updatepkg.Encrypt(strings.NewReader("x"), h, ks.enc.Recipient(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got := updatepkg.FileName(h); got != "sneakers-appliance-0.0.0-lab.20261007d-g1a2b3c4-amd64-LAB.bin" {
		t.Fatal(got)
	}
	for _, v := range []string{"0.0.0-", "0.0.0-lab..1", "0.0.0-lab_1", "0.0.0-lab/1"} {
		h.Version = v
		if _, err := updatepkg.Encrypt(strings.NewReader("x"), h, ks.enc.Recipient(), &bytes.Buffer{}); !codes.Is(err, codes.UpgradeFormat) {
			t.Errorf("%q: want UPGRADE_FORMAT, got %v", v, err)
		}
	}
}
