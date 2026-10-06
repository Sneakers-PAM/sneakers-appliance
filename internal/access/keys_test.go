// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
)

func TestParseLoginKey(t *testing.T) {
	cases := []struct {
		name, fixture string
		code          string // "" means accepted
	}{
		{"ed25519", "testdata/ed25519.pub", ""},
		{"ecdsa256", "testdata/ecdsa256.pub", ""},
		{"ecdsa384", "testdata/ecdsa384.pub", ""},
		{"sk-ed25519", genSKEd25519, ""},
		{"rsa3072", "testdata/rsa3072.pub", ""},
		{"rsa2048", "testdata/rsa2048.pub", "ACCESS_KEY_WEAK"},
		{"dsa", "testdata/dsa.pub", "ACCESS_KEY_WEAK"},
		{"garbage", "testdata/garbage.pub", "ACCESS_KEY_TYPE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := access.ParseLoginKey(readFixture(t, c.fixture))
			assertCode(t, err, c.code)
		})
	}
}

func TestParseLoginKeyNormalizes(t *testing.T) {
	line := readFixture(t, "testdata/ed25519.pub")
	k, err := access.ParseLoginKey("restrict,no-pty " + line)
	assertCode(t, err, "")
	if k.Type != "ssh-ed25519" || k.Comment != "test key" || !strings.HasPrefix(k.Fingerprint, "SHA256:") {
		t.Fatalf("parsed %+v", k)
	}
	if strings.Contains(k.PublicKey, "restrict") || strings.Contains(k.PublicKey, "test key") {
		t.Fatalf("public key keeps options or comment: %q", k.PublicKey)
	}
}

func TestParseLoginKeyRefusesTwoKeys(t *testing.T) {
	two := readFixture(t, "testdata/ed25519.pub") + readFixture(t, "testdata/ecdsa256.pub")
	_, err := access.ParseLoginKey(two)
	assertCode(t, err, "ACCESS_KEY_TYPE")
}

func TestParseRecoveryKey(t *testing.T) {
	cases := []struct {
		name, fixture string
		code          string
	}{
		{"ed25519", "testdata/ed25519.pub", ""},
		{"rsa3072", "testdata/rsa3072.pub", ""},
		{"sk-ed25519", genSKEd25519, "ACCESS_KEY_TYPE"},
		{"ecdsa256", "testdata/ecdsa256.pub", "ACCESS_KEY_TYPE"},
		{"rsa2048", "testdata/rsa2048.pub", "ACCESS_KEY_WEAK"},
		{"dsa", "testdata/dsa.pub", "ACCESS_KEY_WEAK"},
		{"garbage", "testdata/garbage.pub", "ACCESS_KEY_TYPE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := access.ParseRecoveryKey(readFixture(t, c.fixture))
			assertCode(t, err, c.code)
		})
	}
}

func TestValidName(t *testing.T) {
	for name, want := range map[string]bool{
		"alice": true, "bob-2": true, "c_d": true, "a": false, "Alice": false, "1bob": false,
		"root": false, "maint": false, "enrol": false, "sshd": false, "sshkeys": false, "nobody": false, "osadmin": false,
		strings.Repeat("a", 31): true, strings.Repeat("a", 32): false,
	} {
		if got := access.ValidName(name); got != want {
			t.Errorf("ValidName(%q) = %v, want %v", name, got, want)
		}
	}
}
