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

// After a reboot the management addresses come back one at a time (the
// IPv4 lease, then the IPv6 one), and sneakers-osadmin calls EnsureCert
// for each set it sees. The certificate an admin checked on the console
// keeps its fingerprint: a set the certificate already covers keeps it,
// and only a name it doesn't cover makes a new one.
func TestARebootsAddressesComingBackKeepTheCertificate(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	host, v4, v6 := "box1.sneakers.example.org", "192.0.2.10", "2001:db8::10"
	_, first, err := osadmin.EnsureCert(dir, host, []string{v4, v6}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, addrs := range [][]string{{v4}, {v4, v6}, {v6}} {
		_, got, err := osadmin.EnsureCert(dir, host, addrs, now.Add(time.Minute))
		if err != nil || got.Fingerprint != first.Fingerprint {
			t.Fatalf("addresses %v: fingerprint %s, want the one the box had, %s (%v)", addrs, got.Fingerprint, first.Fingerprint, err)
		}
		on, err := osadmin.ReadCertInfo(dir)
		if err != nil || on.Fingerprint != first.Fingerprint {
			t.Fatalf("addresses %v: Status names %s, want %s (%v)", addrs, on.Fingerprint, first.Fingerprint, err)
		}
	}
	_, moved, err := osadmin.EnsureCert(dir, host, []string{v4, "192.0.2.20"}, now.Add(time.Minute))
	if err != nil || moved.Fingerprint == first.Fingerprint {
		t.Fatal("an address the certificate doesn't name makes a new one")
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
