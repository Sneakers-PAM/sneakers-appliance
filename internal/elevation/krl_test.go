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

// OpenSSH's own ssh-keygen reads the revocation list: a used certificate's
// serial is revoked, a fresh one isn't, and the certificate carries the
// principal, validity, options and extensions the design names.
func TestOpenSSHReadsTheCertificateAndTheRevocationList(t *testing.T) {
	bin := sshKeygen(t)
	f := newFixture(t, "alice")
	used := f.request("bob", 30)
	ua, err := f.svc.Approve(f.st, "alice", used.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Begin(ua.Certificate, 1); err != nil {
		t.Fatal(err)
	}
	fresh := f.request("bob", 30)
	fa, err := f.svc.Approve(f.st, "alice", fresh.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	usedFile, freshFile := filepath.Join(dir, "used-cert.pub"), filepath.Join(dir, "fresh-cert.pub")
	if err := os.WriteFile(usedFile, []byte(ua.Certificate+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(freshFile, []byte(fa.Certificate+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	krl := filepath.Join(f.dir, "ssh", elevation.RevokedFile)
	if out, err := keygen(t, bin, "-Q", "-f", krl, usedFile); err == nil || !strings.Contains(out, "REVOKED") {
		t.Fatalf("the used certificate isn't revoked: %v %s", err, out)
	}
	if out, err := keygen(t, bin, "-Q", "-f", krl, freshFile); err != nil || strings.Contains(out, "REVOKED") {
		t.Fatalf("the fresh certificate is revoked: %v %s", err, out)
	}
	out, err := keygen(t, bin, "-L", "-f", freshFile)
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	for _, want := range []string{"user certificate", "elev-" + fresh.ID, "force-command /usr/libexec/sneakers-elevated", "source-address 192.0.2.50", "permit-pty"} {
		if !strings.Contains(out, want) {
			t.Errorf("ssh-keygen -L has no %q:\n%s", want, out)
		}
	}
	for _, refused := range []string{"permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding", "permit-user-rc"} {
		if strings.Contains(out, refused) {
			t.Errorf("ssh-keygen -L shows %q:\n%s", refused, out)
		}
	}
}

func TestAnEmptyRevocationListParses(t *testing.T) {
	bin := sshKeygen(t)
	f := newFixture(t, "alice")
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

// A removed login key is on the list sshd reads, whatever its authorized
// keys file still says, beside the used certificates' serials.
func TestOpenSSHSeesRevokedLoginKeys(t *testing.T) {
	bin := sshKeygen(t)
	f := newFixture(t, "alice")
	used := f.request("bob", 30)
	ua, err := f.svc.Approve(f.st, "alice", used.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Begin(ua.Certificate, 1); err != nil {
		t.Fatal(err)
	}
	st := f.st.Clone()
	gone := st.Admins[0].Keys[0]
	st.RevokedKeys = []access.RevokedKey{{Fingerprint: gone.Fingerprint, PublicKey: gone.PublicKey, Admin: st.Admins[0].Name}}
	if err := f.svc.RevokeLoginKeys(st); err != nil {
		t.Fatal(err)
	}
	krl := filepath.Join(f.dir, "ssh", elevation.RevokedFile)
	if out, err := keygen(t, bin, "-Q", "-f", krl, writeKey(t, f.keys["alice"])); err == nil || !strings.Contains(out, "REVOKED") {
		t.Fatalf("the removed key isn't revoked: %v %s", err, out)
	}
	if out, err := keygen(t, bin, "-Q", "-f", krl, writeKey(t, f.keys["bob"])); err != nil || strings.Contains(out, "REVOKED") {
		t.Fatalf("a kept key is revoked: %v %s", err, out)
	}
	usedFile := filepath.Join(t.TempDir(), "used-cert.pub")
	if err := os.WriteFile(usedFile, []byte(ua.Certificate+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := keygen(t, bin, "-Q", "-f", krl, usedFile); err == nil || !strings.Contains(out, "REVOKED") {
		t.Fatalf("the used certificate's serial left the list: %v %s", err, out)
	}

	// Every later write of the list keeps the key, and un-revoking drops it.
	f.request("bob", 30)
	if out, err := keygen(t, bin, "-Q", "-f", krl, writeKey(t, f.keys["alice"])); err == nil || !strings.Contains(out, "REVOKED") {
		t.Fatalf("a later write dropped the key: %v %s", err, out)
	}
	st.RevokedKeys = nil
	if err := f.svc.RevokeLoginKeys(st); err != nil {
		t.Fatal(err)
	}
	if out, err := keygen(t, bin, "-Q", "-f", krl, writeKey(t, f.keys["alice"])); err != nil || strings.Contains(out, "REVOKED") {
		t.Fatalf("an un-revoked key is still revoked: %v %s", err, out)
	}
}

// accessd opens the service before the store: the keys already revoked go
// on the very first list it writes.
func TestTheFirstListCarriesTheKeysAlreadyRevoked(t *testing.T) {
	bin := sshKeygen(t)
	f := newFixture(t, "alice")
	dir := t.TempDir()
	if _, err := elevation.Open(elevation.Options{
		SSHDir: filepath.Join(dir, "ssh"), StateFile: filepath.Join(dir, "access", "elevation.json"),
		RevokedKeys: []ssh.PublicKey{f.keys["bob"]},
	}); err != nil {
		t.Fatal(err)
	}
	krl := filepath.Join(dir, "ssh", elevation.RevokedFile)
	if out, err := keygen(t, bin, "-Q", "-f", krl, writeKey(t, f.keys["bob"])); err == nil || !strings.Contains(out, "REVOKED") {
		t.Fatalf("not revoked: %v %s", err, out)
	}
}
