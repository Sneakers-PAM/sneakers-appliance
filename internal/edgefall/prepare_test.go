// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package edgefall_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/edgefall"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
)

func osadminDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	l := testpki.NewTLSCA(t).Issue(t, testpki.LeafOptions{Names: []string{"box.example.org"}})
	for name, b := range map[string][]byte{"tls.crt": l.PEM, "tls.key": l.KeyPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// prepare (root, before every start) copies the box's :8443 certificate,
// the one Traefik's box-tls Secret carries, into edgefall's own directory,
// which only edgefall reads; serve loads it from there.
func TestPrepareCopiesTheBoxCertificateForEdgefall(t *testing.T) {
	src := osadminDir(t)
	dst := filepath.Join(t.TempDir(), "edgefall")
	if err := edgefall.Prepare(src, dst, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dst)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("dir %v %v", st, err)
	}
	for _, name := range []string{"tls.crt", "tls.key"} {
		st, err := os.Stat(filepath.Join(dst, name))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, st, err)
		}
	}
	if _, err := edgefall.LoadCert(dst)(); err != nil {
		t.Fatal(err)
	}
}

// osadmin can write its directory, so a link planted there is never
// followed, and a pair that isn't one isn't copied.
func TestPrepareFollowsNoLinksAndCopiesOnlyAPair(t *testing.T) {
	src := osadminDir(t)
	if err := os.Remove(filepath.Join(src, "tls.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/shadow", filepath.Join(src, "tls.key")); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "edgefall")
	if err := edgefall.Prepare(src, dst, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "tls.key")); !os.IsNotExist(err) {
		t.Fatalf("a linked key was copied: %v", err)
	}
	if _, err := edgefall.LoadCert(dst)(); err == nil {
		t.Fatal("a certificate loaded without its key")
	}
}

// With no certificate yet, prepare leaves none behind, and edgefall
// claims nothing (TestNoCertificateNoClaim).
func TestPrepareWithoutACertificateLeavesNone(t *testing.T) {
	dst := filepath.Join(t.TempDir(), "edgefall")
	if err := edgefall.Prepare(osadminDir(t), dst, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if err := edgefall.Prepare(t.TempDir(), dst, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tls.crt", "tls.key"} {
		if _, err := os.Stat(filepath.Join(dst, name)); !os.IsNotExist(err) {
			t.Fatalf("%s left behind: %v", name, err)
		}
	}
}
