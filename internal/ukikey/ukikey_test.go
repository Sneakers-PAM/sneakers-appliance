// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package ukikey_test

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"io"
	"testing"
	"testing/fstest"
	"unicode/utf16"

	"filippo.io/age"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/ukikey"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/ukipcr"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

func unsignedUKI(t *testing.T) []byte {
	t.Helper()
	return fixtures.PE(t,
		fixtures.Section{Name: ".osrel", Data: []byte("ID=sneakers\n")},
		fixtures.Section{Name: ".cmdline", Data: []byte("quiet")},
		fixtures.Section{Name: ".uname", Data: []byte("6.12.0-sneakers")},
		fixtures.Section{Name: ".sbat", Data: []byte("sbat,1\n")},
		fixtures.Section{Name: ".linux", Data: bytes.Repeat([]byte{0x90}, 5000)},
		fixtures.Section{Name: ".initrd", Data: bytes.Repeat([]byte{0x07}, 3000)},
	)
}

func newKey(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func keyFile(id *age.X25519Identity) []byte {
	return []byte("# Sneakers-PAM LAB ephemeral NOT FOR PRODUCTION update key\n" + id.String() + "\n")
}

func sections(t *testing.T, img []byte) map[string][]byte {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(img))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, s := range f.Sections {
		b, err := io.ReadAll(s.Open())
		if err != nil {
			t.Fatal(err)
		}
		out[s.Name] = b[:min(int(s.VirtualSize), len(b))]
	}
	return out
}

func TestEmbedThenReadGivesTheSameKey(t *testing.T) {
	id := newKey(t)
	in := unsignedUKI(t)
	out, err := ukikey.Embed(in, keyFile(id))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ukikey.Identity(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if got.Recipient().String() != id.Recipient().String() {
		t.Fatal("the embedded key isn't the one handed in")
	}
	before, after := sections(t, in), sections(t, out)
	for name, b := range before {
		if !bytes.Equal(after[name], b) {
			t.Fatalf("section %s changed", name)
		}
	}
	if string(after[ukikey.Section]) != id.String() {
		t.Fatalf("section %s holds %q, want only the key", ukikey.Section, after[ukikey.Section])
	}
}

func TestTheEmbeddedImageSignsAndPredictsTheSame(t *testing.T) {
	in := unsignedUKI(t)
	out, err := ukikey.Embed(in, keyFile(newKey(t)))
	if err != nil {
		t.Fatal(err)
	}
	signed := fixtures.Sign(t, testpki.SelfSigned(t, "db"), out)
	want, err := ukipcr.Predict(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ukipcr.Predict(signed)
	if err != nil {
		t.Fatalf("the signed image with the key section can't be predicted: %v", err)
	}
	if !bytes.Equal(got.Value, want.Value) {
		t.Fatal("the key section changed the PCR 11 prediction; systemd-stub doesn't measure it")
	}
	if _, err := ukikey.Identity(bytes.NewReader(signed)); err != nil {
		t.Fatalf("the key doesn't read back after signing: %v", err)
	}
}

func TestEmbedRefuses(t *testing.T) {
	id := newKey(t)
	in := unsignedUKI(t)
	once, err := ukikey.Embed(in, keyFile(id))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		img, key []byte
	}{
		"a signed image":         {fixtures.Sign(t, testpki.SelfSigned(t, "db"), in), keyFile(id)},
		"a second key":           {once, keyFile(id)},
		"a key that isn't age":   {in, []byte("not a key\n")},
		"two keys":               {in, append(keyFile(id), keyFile(newKey(t))...)},
		"an image that isn't PE": {[]byte("MZ nope"), keyFile(id)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ukikey.Embed(c.img, c.key); err == nil {
				t.Fatal("embedded")
			}
		})
	}
}

func TestAnImageWithoutTheSectionHasNoKey(t *testing.T) {
	_, err := ukikey.Identity(bytes.NewReader(unsignedUKI(t)))
	if !codes.Is(err, codes.UpgradeDecrypt) {
		t.Fatalf("got %v, want UPGRADE_DECRYPT", err)
	}
}

// encrypted packs a tiny payload to r and verifies it, the way the release
// workflow and then the box do.
func encrypted(t *testing.T, r *age.X25519Recipient) *updatepkg.Package {
	t.Helper()
	sign := testpki.ECDSA(t)
	var ct bytes.Buffer
	h, err := updatepkg.Encrypt(bytes.NewReader([]byte("payload")),
		updatepkg.Header{Version: "0.2.0", Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelLab}, r, &ct)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := updatepkg.Seal(&b, hdr, sign.BlobBundle(t, hdr), &ct); err != nil {
		t.Fatal(err)
	}
	p, err := updatepkg.Read(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(sign.PublicPEM, release.ChannelLab); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestALabImageCantDecryptAProductionPackageAndTheReverse(t *testing.T) {
	lab, prod := newKey(t), newKey(t)
	labUKI, err := ukikey.Embed(unsignedUKI(t), keyFile(lab))
	if err != nil {
		t.Fatal(err)
	}
	prodUKI, err := ukikey.Embed(unsignedUKI(t), keyFile(prod))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		uki  []byte
		to   *age.X25519Recipient
		ok   bool
	}{
		{"lab image, lab package", labUKI, lab.Recipient(), true},
		{"prod image, prod package", prodUKI, prod.Recipient(), true},
		{"lab image, prod package", labUKI, prod.Recipient(), false},
		{"prod image, lab package", prodUKI, lab.Recipient(), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			id, err := ukikey.Identity(bytes.NewReader(c.uki))
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			err = encrypted(t, c.to).Decrypt(id, &out)
			if c.ok && (err != nil || out.String() != "payload") {
				t.Fatalf("decrypt: %v", err)
			}
			if !c.ok && !codes.Is(err, codes.UpgradeDecrypt) {
				t.Fatalf("got %v, want UPGRADE_DECRYPT", err)
			}
		})
	}
}

type vars map[string][]byte

func (v vars) Get(name, guid string) (uint32, []byte, error) {
	b, ok := v[name+"-"+guid]
	if !ok {
		return 0, nil, secureboot.ErrNotFound
	}
	return 6, b, nil
}

func (v vars) Write(string, string, uint32, []byte) error { panic("read only") }

func utf16z(s string) []byte {
	var b bytes.Buffer
	for _, u := range utf16.Encode([]rune(s)) {
		_ = binary.Write(&b, binary.LittleEndian, u)
	}
	b.Write([]byte{0, 0})
	return b.Bytes()
}

func TestRunningReadsTheBootedEntrysKey(t *testing.T) {
	booted, other := newKey(t), newKey(t)
	bootedUKI, err := ukikey.Embed(unsignedUKI(t), keyFile(booted))
	if err != nil {
		t.Fatal(err)
	}
	otherUKI, err := ukikey.Embed(unsignedUKI(t), keyFile(other))
	if err != nil {
		t.Fatal(err)
	}
	esp := fstest.MapFS{
		"EFI/Linux/sneakers-0.2.0+2-1.efi": {Data: bootedUKI},
		"EFI/Linux/sneakers-0.1.0.efi":     {Data: otherUKI},
	}
	v := vars{"LoaderEntrySelected-" + ukikey.LoaderGUID: utf16z("sneakers-0.2.0.efi")}
	id, err := ukikey.Running(v, esp)
	if err != nil {
		t.Fatal(err)
	}
	if id.Recipient().String() != booted.Recipient().String() {
		t.Fatal("read the key of an entry that didn't boot")
	}
	if _, err := ukikey.Running(vars{}, esp); !codes.Is(err, codes.UpgradeDecrypt) {
		t.Fatalf("no LoaderEntrySelected: got %v, want UPGRADE_DECRYPT", err)
	}
	v = vars{"LoaderEntrySelected-" + ukikey.LoaderGUID: utf16z("sneakers-0.3.0.efi")}
	if _, err := ukikey.Running(v, esp); !codes.Is(err, codes.UpgradeDecrypt) {
		t.Fatalf("booted entry gone: got %v, want UPGRADE_DECRYPT", err)
	}
}
