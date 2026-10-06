// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

var t0 = time.Date(2026, 10, 5, 14, 0, 0, 0, time.UTC)

// genSKEd25519 stands for a FIDO ed25519 key made at run time: its type
// name has an address form, so it isn't kept as a fixture file.
const genSKEd25519 = "gen:sk-ed25519"

func readFixture(t *testing.T, path string) string {
	t.Helper()
	if path == genSKEd25519 {
		return skEd25519Line(t)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// assertCode fails unless err carries the code named by symbol; "" means no
// error.
func assertCode(t *testing.T, err error, symbol string) {
	t.Helper()
	if symbol == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("no error, want %s", symbol)
	}
	c, ok := codes.Of(err)
	if !ok || codes.Symbol(c) != symbol {
		t.Fatalf("got %v, want %s", err, symbol)
	}
}

func ed25519Line(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " test key"
}

func skEd25519Line(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := ssh.Marshal(struct{ Name, Key, App string }{ssh.KeyAlgoSKED25519, string(pub), "ssh:"})
	pk, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " test key"
}

func loginKey(t *testing.T) access.AdminKey {
	t.Helper()
	k, err := access.ParseLoginKey(ed25519Line(t))
	if err != nil {
		t.Fatal(err)
	}
	return access.AdminKey{Key: k, Added: t0, AddedBy: "console", Via: access.ViaEnrol}
}

func recoveryKeys(t *testing.T, n int) []access.RecoveryKey {
	t.Helper()
	out := make([]access.RecoveryKey, 0, n)
	for range n {
		k, err := access.ParseRecoveryKey(ed25519Line(t))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, access.RecoveryKey{Key: k, Set: t0, SetBy: "alice"})
	}
	return out
}

func stateWithOwner(name string, keys ...access.AdminKey) access.State {
	s := access.State{NextUID: access.FirstUID, ElevationPolicy: access.DefaultPolicy()}
	a := s.AddAdmin(name, access.RoleOwner, "console", t0)
	a.Keys = append(a.Keys, keys...)
	return s
}
