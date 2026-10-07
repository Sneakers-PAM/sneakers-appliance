// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

func TestEnsureCert(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	c, info, err := osadmin.EnsureCert(dir, "box1.sneakers.example.org", []string{"192.0.2.10", "2001:db8::10"}, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf := c.Leaf
	if k, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || k.Curve != elliptic.P256() {
		t.Fatal("ECDSA P-256")
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "box1.sneakers.example.org" || len(leaf.IPAddresses) != 2 {
		t.Fatalf("SANs %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
	if !info.SelfSigned || info.Fingerprint != osadmin.Fingerprint(leaf.Raw) || len(info.Fingerprint) != 95 {
		t.Fatalf("%+v", info)
	}
	st, err := os.Stat(filepath.Join(dir, "tls.key"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatal("the key is 0600")
	}

	_, again, err := osadmin.EnsureCert(dir, "box1.sneakers.example.org", []string{"2001:db8::10", "192.0.2.10"}, now.Add(24*time.Hour))
	if err != nil || again.Fingerprint != info.Fingerprint {
		t.Fatal("the same names keep the certificate")
	}
	_, renamed, err := osadmin.EnsureCert(dir, "box2.sneakers.example.org", []string{"192.0.2.10"}, now)
	if err != nil || renamed.Fingerprint == info.Fingerprint {
		t.Fatal("a new name makes a new certificate")
	}
	_, late, err := osadmin.EnsureCert(dir, "box2.sneakers.example.org", []string{"192.0.2.10"}, renamed.Expires.Add(-time.Hour))
	if err != nil || late.Fingerprint == renamed.Fingerprint {
		t.Fatal("a certificate near its end is replaced")
	}
}

// accessd describes the certificate for Status without reading the key,
// and doesn't follow a link sneakers-osadmin could plant.
func TestReadCertInfo(t *testing.T) {
	dir := t.TempDir()
	_, info, err := osadmin.EnsureCert(dir, "box1.sneakers.example.org", []string{"192.0.2.10"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "tls.key")); err != nil {
		t.Fatal(err)
	}
	got, err := osadmin.ReadCertInfo(dir)
	if err != nil || got != info {
		t.Fatalf("%+v %v, want %+v", got, err, info)
	}
	other := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "tls.crt"), filepath.Join(other, "tls.crt")); err != nil {
		t.Fatal(err)
	}
	if _, err := osadmin.ReadCertInfo(other); err == nil {
		t.Fatal("followed a link")
	}
}
