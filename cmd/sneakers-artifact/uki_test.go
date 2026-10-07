// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

func fixtureUKI(t *testing.T) []byte {
	t.Helper()
	return fixtures.PE(t,
		fixtures.Section{Name: ".osrel", Data: []byte("ID=sneakers\n")},
		fixtures.Section{Name: ".cmdline", Data: []byte("quiet")},
		fixtures.Section{Name: ".uname", Data: []byte("6.12.0-sneakers")},
		fixtures.Section{Name: ".linux", Data: bytes.Repeat([]byte{0x90}, 3000)},
	)
}

// labBin makes a lab key set and a sealed lab .bin encrypted to its
// update.pub, and returns the key directory, the release key and the .bin.
func labBin(t *testing.T, tmp string) (keys, pub, bin string) {
	t.Helper()
	keys, layout, work := filepath.Join(tmp, "keys"), filepath.Join(tmp, "layout"), filepath.Join(tmp, "work")
	for _, name := range []string{"update", "rogue-update"} {
		if _, err := runCmd(t, "lab-update-key", "--out", keys, "--name", name); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(layout, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(layout, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`))
	header, err := runCmd(t, "bin-pack", "--layout", layout, "--recipient", filepath.Join(keys, "update.pub"),
		"--version", "0.2.0", "--channel", "lab", "--out", work)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := os.ReadFile(header) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	sign := testpki.ECDSA(t)
	writeFile(t, filepath.Join(work, "header.sigstore.json"), sign.BlobBundle(t, hdr))
	pub = filepath.Join(tmp, "cosign.pub")
	writeFile(t, pub, sign.PublicPEM)
	bin, err = runCmd(t, "bin-seal", "--work", work, "--bundle", filepath.Join(work, "header.sigstore.json"), "--out", filepath.Join(tmp, "out"))
	if err != nil {
		t.Fatal(err)
	}
	return keys, pub, bin
}

// TestTheBoxDecryptsWithTheKeyInItsUKI follows the sign job: the update key
// goes into the unsigned UKI, the UKI is signed, and the .bin then decrypts
// with the key read back out of the signed UKI, as the box reads it.
func TestTheBoxDecryptsWithTheKeyInItsUKI(t *testing.T) {
	tmp := t.TempDir()
	keys, pub, bin := labBin(t, tmp)
	in, keyed := filepath.Join(tmp, "unsigned.efi"), filepath.Join(tmp, "keyed.efi")
	writeFile(t, in, fixtureUKI(t))
	if _, err := runCmd(t, "uki-add-key", "--uki", in, "--key", filepath.Join(keys, "update.key"),
		"--recipient", filepath.Join(keys, "update.pub"), "--out", keyed); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(keyed) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	signed := filepath.Join(tmp, "signed.efi")
	writeFile(t, signed, fixtures.Sign(t, testpki.SelfSigned(t, "db"), b))

	extract := filepath.Join(tmp, "x")
	got, err := runCmd(t, "bin-verify", "--release-key", pub, "--channel", "lab", "--identity-uki", signed, "--extract", extract, bin)
	if err != nil {
		t.Fatal(err)
	}
	if got != "verified sneakers-appliance 0.2.0 amd64 full (lab)" {
		t.Fatalf("verify printed %q", got)
	}
	if _, err := os.Stat(filepath.Join(extract, "oci-layout")); err != nil {
		t.Fatalf("nothing was unpacked: %v", err)
	}
}

func TestUKIAddKeyRefusesAKeyThatIsntTheRecipients(t *testing.T) {
	tmp := t.TempDir()
	keys, _, _ := labBin(t, tmp)
	in, out := filepath.Join(tmp, "unsigned.efi"), filepath.Join(tmp, "keyed.efi")
	writeFile(t, in, fixtureUKI(t))
	_, err := runCmd(t, "uki-add-key", "--uki", in, "--key", filepath.Join(keys, "rogue-update.key"),
		"--recipient", filepath.Join(keys, "update.pub"), "--out", out)
	if err == nil || !strings.Contains(err.Error(), "doesn't belong to") {
		t.Fatalf("a key for another recipient: %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("a refused embed wrote %s: %v", out, err)
	}
}

func decrypt(err error) bool { return codes.Is(err, codes.UpgradeDecrypt) }

func TestBinVerifyWithTheWrongUKIRefuses(t *testing.T) {
	tmp := t.TempDir()
	keys, pub, bin := labBin(t, tmp)
	bare, rogue := filepath.Join(tmp, "bare.efi"), filepath.Join(tmp, "rogue.efi")
	writeFile(t, bare, fixtureUKI(t))
	if _, err := runCmd(t, "uki-add-key", "--uki", bare, "--key", filepath.Join(keys, "rogue-update.key"),
		"--recipient", filepath.Join(keys, "rogue-update.pub"), "--out", rogue); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		args []string
		ok   func(error) bool
	}{
		"a UKI without a key":    {[]string{"--identity-uki", bare}, decrypt},
		"a UKI with another key": {[]string{"--identity-uki", rogue}, decrypt},
		"both --identity and a UKI": {[]string{"--identity-uki", rogue, "--identity", filepath.Join(keys, "update.key")}, func(err error) bool {
			return strings.Contains(err.Error(), "none of the others can be")
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"bin-verify", "--release-key", pub, "--channel", "lab"}, c.args...)
			_, err := runCmd(t, append(args, bin)...)
			if err == nil || !c.ok(err) {
				t.Fatalf("got %v", err)
			}
		})
	}
}
