// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package elevation_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
)

func sshKeygen(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		if os.Getenv("SNEAKERS_REQUIRE_TOOLS") != "" {
			t.Fatal("ssh-keygen isn't installed and SNEAKERS_REQUIRE_TOOLS is set")
		}
		t.Skip("ssh-keygen isn't installed")
	}
	return p
}

func keygen(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput() // #nosec G204 -- the test's own ssh-keygen
	return string(out), err
}

func TestAnEmptyRevocationListParses(t *testing.T) {
	bin := sshKeygen(t)
	f := newFixture(t)
	k := f.keys["bob"]
	file := filepath.Join(t.TempDir(), "bob.pub")
	if err := os.WriteFile(file, ssh.MarshalAuthorizedKey(k), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := keygen(t, bin, "-Q", "-f", filepath.Join(f.dir, "ssh", elevation.RevokedFile), file); err != nil {
		t.Fatalf("%v %s", err, out)
	}
}

// writeKey writes k as a .pub file and returns its path.
func writeKey(t *testing.T, k ssh.PublicKey) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "key.pub")
	if err := os.WriteFile(file, ssh.MarshalAuthorizedKey(k), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// A removed SSH key is on the list sshd reads, by its key and its
// certificate's serial; un-revoking drops both.
func TestOpenSSHSeesRevokedKeysAndSerials(t *testing.T) {
	bin := sshKeygen(t)
	f := newFixture(t)
	now := time.Now()
	cert, err := f.root.IssueUserCert(f.keys["alice"], "alice", 5, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	keep, err := f.root.IssueUserCert(f.keys["bob"], "bob", 6, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	st := f.st.Clone()
	gone := st.Admins[0].Keys[0]
	st.RevokedKeys = []access.RevokedKey{{Fingerprint: gone.Fingerprint, PublicKey: gone.PublicKey, Admin: "alice", Serial: 5}}
	if err := f.svc.RevokeLoginKeys(st); err != nil {
		t.Fatal(err)
	}
	krl := filepath.Join(f.dir, "ssh", elevation.RevokedFile)
	for name, k := range map[string]ssh.PublicKey{"key": f.keys["alice"], "certificate": cert} {
		if out, err := keygen(t, bin, "-Q", "-f", krl, writeKey(t, k)); err == nil || !strings.Contains(out, "REVOKED") {
			t.Fatalf("the removed %s isn't revoked: %v %s", name, err, out)
		}
	}
	if out, err := keygen(t, bin, "-Q", "-f", krl, writeKey(t, keep)); err != nil || strings.Contains(out, "REVOKED") {
		t.Fatalf("a kept certificate is revoked: %v %s", err, out)
	}
	st.RevokedKeys = nil
	if err := f.svc.RevokeLoginKeys(st); err != nil {
		t.Fatal(err)
	}
	if out, err := keygen(t, bin, "-Q", "-f", krl, writeKey(t, cert)); err != nil || strings.Contains(out, "REVOKED") {
		t.Fatalf("an un-revoked certificate is still revoked: %v %s", err, out)
	}
}

// accessd opens the service before the store: the keys already revoked go
// on the very first list it writes.
func TestTheFirstListCarriesTheKeysAlreadyRevoked(t *testing.T) {
	bin := sshKeygen(t)
	f := newFixture(t)
	dir := t.TempDir()
	if _, err := elevation.Open(elevation.Options{
		RootKey: f.root, SSHDir: filepath.Join(dir, "ssh"), StateFile: filepath.Join(dir, "access", "elevation.json"),
		RevokedKeys: []ssh.PublicKey{f.keys["bob"]},
	}); err != nil {
		t.Fatal(err)
	}
	krl := filepath.Join(dir, "ssh", elevation.RevokedFile)
	if out, err := keygen(t, bin, "-Q", "-f", krl, writeKey(t, f.keys["bob"])); err == nil || !strings.Contains(out, "REVOKED") {
		t.Fatalf("not revoked: %v %s", err, out)
	}
}
