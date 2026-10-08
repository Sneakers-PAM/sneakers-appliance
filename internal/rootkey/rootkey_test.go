// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package rootkey_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootkey"
)

// memSealer is KeyCustody in memory: what is sealed comes back.
type memSealer struct {
	items map[string][]byte
	fail  error
}

func newSealer() *memSealer { return &memSealer{items: map[string][]byte{}} }

func (m *memSealer) Seal(name string, secret []byte) error {
	if m.fail != nil {
		return m.fail
	}
	m.items[name] = bytes.Clone(secret)
	return nil
}

func (m *memSealer) Unseal(name string) ([]byte, bool, error) {
	b, ok := m.items[name]
	return bytes.Clone(b), ok, nil
}

func TestTheFirstStartMakesAndSealsTheRootKeyAndPepper(t *testing.T) {
	dir := t.TempDir()
	s := newSealer()
	k, err := rootkey.Load(s, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if k.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("root key type %s", k.PublicKey().Type())
	}
	if _, ok := s.items[rootkey.SealedName]; !ok {
		t.Fatal("the root key wasn't sealed")
	}
	if len(k.Pepper()) != rootkey.PepperSize {
		t.Fatalf("pepper is %d bytes", len(k.Pepper()))
	}
	if !bytes.Equal(s.items[rootkey.PepperName], k.Pepper()) {
		t.Fatal("the pepper wasn't sealed")
	}
	pub, err := os.ReadFile(filepath.Join(dir, rootkey.PublicFile))
	if err != nil {
		t.Fatal(err)
	}
	got, _, _, _, err := ssh.ParseAuthorizedKey(pub)
	if err != nil || !bytes.Equal(got.Marshal(), k.PublicKey().Marshal()) {
		t.Fatalf("root_key.pub isn't the root key's public half: %v", err)
	}
	// Nothing on the state volume holds the private key.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if bytes.Contains(b, []byte("PRIVATE KEY")) {
			t.Fatalf("%s holds a private key", e.Name())
		}
	}
}

func TestTheNextStartUnsealsTheSameKey(t *testing.T) {
	s := newSealer()
	a, err := rootkey.Load(s, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := rootkey.Load(s, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Fingerprint() != b.Fingerprint() || !bytes.Equal(a.Pepper(), b.Pepper()) {
		t.Fatal("a second start made a new root key or pepper")
	}
}

func TestASealFailureStopsTheStart(t *testing.T) {
	s := newSealer()
	s.fail = errors.New("custody down")
	if _, err := rootkey.Load(s, t.TempDir(), nil); err == nil {
		t.Fatal("a root key that can't be sealed must not be used")
	}
}

func TestIssuedCertificatesVerifyAgainstTheRootKey(t *testing.T) {
	k, err := rootkey.Load(newSealer(), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	spk, _ := ssh.NewPublicKey(pub)
	now := time.Date(2026, 10, 7, 14, 0, 0, 0, time.UTC)
	cert, err := k.IssueUserCert(spk, "alice", 7, now, now.Add(365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if cert.Serial != 7 || cert.CertType != ssh.UserCert || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "alice" {
		t.Fatalf("certificate fields %+v", cert)
	}
	if _, ok := cert.Extensions["permit-pty"]; !ok || len(cert.Extensions) != 1 || len(cert.CriticalOptions) != 0 {
		t.Fatalf("extensions %v, options %v", cert.Extensions, cert.CriticalOptions)
	}
	if !strings.Contains(cert.KeyId, "alice") || !strings.Contains(cert.KeyId, "serial=7") {
		t.Fatalf("key id %q", cert.KeyId)
	}
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool { return bytes.Equal(auth.Marshal(), k.PublicKey().Marshal()) },
		Clock:           func() time.Time { return now.Add(time.Hour) },
	}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Fatalf("the certificate doesn't check: %v", err)
	}
	if err := checker.CheckCert("bob", cert); err == nil {
		t.Fatal("the certificate works for another name")
	}
}

func TestCodesAreDeterministicAndTiedToTheMessage(t *testing.T) {
	k, err := rootkey.Load(newSealer(), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	a, b := k.Code([]byte("challenge A")), k.Code([]byte("challenge A"))
	if a != b {
		t.Fatal("the same message gave two codes")
	}
	if a == k.Code([]byte("challenge B")) {
		t.Fatal("two messages gave the same code")
	}
	if len(a) != 9 || a[4] != '-' {
		t.Fatalf("code %q isn't XXXX-XXXX", a)
	}
	other, _ := rootkey.Load(newSealer(), t.TempDir(), nil)
	if other.Code([]byte("challenge A")) == a {
		t.Fatal("another box's root key gave the same code")
	}
}
