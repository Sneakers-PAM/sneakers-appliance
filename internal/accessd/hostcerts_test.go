// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootkey"
)

func hostCert(t *testing.T, path string) *ssh.Certificate {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- a test file
	if err != nil {
		t.Fatal(err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatalf("%s isn't a certificate", path)
	}
	return c
}

// Each host key gets a host certificate from the host CA for the box's
// names and addresses; it's signed again when they change, or the key,
// and left alone otherwise.
func TestHostCertificatesFollowTheKeysAndNames(t *testing.T) {
	dir := t.TempDir()
	root, err := rootkey.Load(newMemSealer(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := accessd.EnsureHostKeys(dir); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	names := []string{"box1.sneakers.example.org", "192.0.2.10"}
	changed, err := accessd.SignHostCerts(root, dir, names, now)
	if err != nil || !changed {
		t.Fatalf("%v %v", changed, err)
	}
	for _, kind := range []string{"ed25519", "rsa"} {
		c := hostCert(t, filepath.Join(dir, "ssh_host_"+kind+"_key-cert.pub"))
		pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(read(t, filepath.Join(dir, "ssh_host_"+kind+"_key.pub"))))
		if c.CertType != ssh.HostCert || !slices.Equal(c.ValidPrincipals, names) || !bytes.Equal(c.Key.Marshal(), pub.Marshal()) || !bytes.Equal(c.SignatureKey.Marshal(), root.HostCAPublicKey().Marshal()) {
			t.Fatalf("%s: %+v", kind, c)
		}
	}
	before := read(t, filepath.Join(dir, "ssh_host_ed25519_key-cert.pub"))
	if changed, err := accessd.SignHostCerts(root, dir, names, now.Add(time.Hour)); err != nil || changed {
		t.Fatalf("the same names signed again: %v %v", changed, err)
	}
	if changed, err := accessd.SignHostCerts(root, dir, []string{"box1.sneakers.example.org", "192.0.2.20"}, now); err != nil || !changed {
		t.Fatalf("a new address: %v %v", changed, err)
	}
	if c := hostCert(t, filepath.Join(dir, "ssh_host_ed25519_key-cert.pub")); !slices.Contains(c.ValidPrincipals, "192.0.2.20") {
		t.Fatalf("principals %v", c.ValidPrincipals)
	}
	// A new host key gets a new certificate.
	for _, f := range []string{"ssh_host_ed25519_key", "ssh_host_ed25519_key.pub"} {
		if err := os.Rename(filepath.Join(dir, f), filepath.Join(dir, "old-"+f)); err != nil {
			t.Fatal(err)
		}
	}
	if err := accessd.EnsureHostKeys(dir); err != nil {
		t.Fatal(err)
	}
	if changed, err := accessd.SignHostCerts(root, dir, []string{"box1.sneakers.example.org", "192.0.2.20"}, now); err != nil || !changed {
		t.Fatalf("a new key: %v %v", changed, err)
	}
	if read(t, filepath.Join(dir, "ssh_host_ed25519_key-cert.pub")) == before {
		t.Fatal("the certificate didn't follow the new key")
	}
	// Close to its end it's renewed.
	if changed, err := accessd.SignHostCerts(root, dir, []string{"box1.sneakers.example.org", "192.0.2.20"}, now.Add(340*24*time.Hour)); err != nil || !changed {
		t.Fatalf("near its end: %v %v", changed, err)
	}
	if strings.Contains(read(t, filepath.Join(dir, "ssh_host_rsa_key-cert.pub")), "PRIVATE") {
		t.Fatal("a private key in a certificate file")
	}
}

// accessd signs the host certificates as it renders sshd's files, for the
// host name and the management addresses sshd listens on (link-local ones
// left out), and sshd's config presents them.
func TestAccessdSignsTheHostCertificatesWhenItRenders(t *testing.T) {
	b := newBox(t)
	dir := filepath.Join(b.state, "ssh")
	if err := accessd.EnsureHostKeys(dir); err != nil {
		t.Fatal(err)
	}
	b.d.Rerender()
	c := hostCert(t, filepath.Join(dir, "ssh_host_ed25519_key-cert.pub"))
	if !slices.Equal(c.ValidPrincipals, []string{"box1.sneakers.example.org", "192.0.2.10", "2001:db8::10"}) {
		t.Fatalf("principals %v", c.ValidPrincipals)
	}
}
