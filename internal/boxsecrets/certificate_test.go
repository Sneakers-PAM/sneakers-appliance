// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxsecrets_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsecrets"
)

const certSpec = `format: 2
box_secrets:
  - secret: sneakers/sneakers-pgha-tls
    certificate:
      common_name: db-primary.sneakers.svc
      dns_names: [db-primary, "*.db-headless.sneakers.svc"]
`

func certOf(t *testing.T, s secret) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode([]byte(s.StringData["tls.crt"]))
	if blk == nil {
		t.Fatalf("no certificate in %q", s.StringData["tls.crt"])
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestABoxCertificateIsMadeOnceAndKept(t *testing.T) {
	st := &boxsecrets.Store{Dir: t.TempDir(), Manifests: t.TempDir()}
	sl := slot(t, certSpec)
	if err := st.Ensure(sl); err != nil {
		t.Fatal(err)
	}
	s := readStack(t, st.Manifests)["sneakers/sneakers-pgha-tls"]
	if _, err := tls.X509KeyPair([]byte(s.StringData["tls.crt"]), []byte(s.StringData["tls.key"])); err != nil {
		t.Fatalf("the pair doesn't load: %v", err)
	}
	c := certOf(t, s)
	if !slices.Equal(c.DNSNames, []string{"db-primary", "*.db-headless.sneakers.svc"}) || c.Subject.CommonName != "db-primary.sneakers.svc" {
		t.Fatalf("names: %q %v", c.Subject.CommonName, c.DNSNames)
	}
	if !slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth) || !slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		t.Fatalf("usages: %v", c.ExtKeyUsage)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(s.StringData["ca.crt"])) {
		t.Fatal("ca.crt doesn't parse")
	}
	if _, err := c.Verify(x509.VerifyOptions{Roots: roots, DNSName: "db-primary", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("ca.crt doesn't verify the certificate: %v", err)
	}
	if err := st.Ensure(sl); err != nil {
		t.Fatal(err)
	}
	if again := readStack(t, st.Manifests)["sneakers/sneakers-pgha-tls"]; again.StringData["tls.key"] != s.StringData["tls.key"] {
		t.Fatal("an apply replaced a certificate with years left")
	}
}

func TestABoxCertificateIsRenewedAtAnApplyInItsLastYear(t *testing.T) {
	now := time.Now()
	st := &boxsecrets.Store{Dir: t.TempDir(), Manifests: t.TempDir(), Now: func() time.Time { return now }}
	sl := slot(t, certSpec)
	if err := st.Ensure(sl); err != nil {
		t.Fatal(err)
	}
	first := readStack(t, st.Manifests)["sneakers/sneakers-pgha-tls"]
	now = certOf(t, first).NotAfter.Add(-boxsecrets.CertificateRenewBefore - time.Hour)
	if err := st.Ensure(sl); err != nil {
		t.Fatal(err)
	}
	if kept := readStack(t, st.Manifests)["sneakers/sneakers-pgha-tls"]; kept.StringData["tls.crt"] != first.StringData["tls.crt"] {
		t.Fatal("renewed before its last year")
	}
	now = certOf(t, first).NotAfter.Add(-boxsecrets.CertificateRenewBefore + time.Hour)
	if err := st.Ensure(sl); err != nil {
		t.Fatal(err)
	}
	renewed := readStack(t, st.Manifests)["sneakers/sneakers-pgha-tls"]
	if renewed.StringData["tls.crt"] == first.StringData["tls.crt"] || renewed.StringData["ca.crt"] != renewed.StringData["tls.crt"] {
		t.Fatal("not renewed in its last year")
	}
	if !certOf(t, renewed).NotAfter.After(certOf(t, first).NotAfter) {
		t.Fatal("the renewed certificate doesn't last longer")
	}
}

func TestABoxCertificateFollowsTheNamesTheBundleDeclares(t *testing.T) {
	st := &boxsecrets.Store{Dir: t.TempDir(), Manifests: t.TempDir()}
	if err := st.Ensure(slot(t, certSpec)); err != nil {
		t.Fatal(err)
	}
	const other = `format: 2
box_secrets:
  - secret: sneakers/sneakers-pgha-tls
    certificate:
      common_name: db-primary.sneakers.svc
      dns_names: [other-primary]
`
	if err := st.Ensure(slot(t, other)); err != nil {
		t.Fatal(err)
	}
	if c := certOf(t, readStack(t, st.Manifests)["sneakers/sneakers-pgha-tls"]); !slices.Equal(c.DNSNames, []string{"other-primary"}) {
		t.Fatalf("names: %v", c.DNSNames)
	}
}

func TestABoxCertificateInTheValuesFileIsPrivate(t *testing.T) {
	st := &boxsecrets.Store{Dir: t.TempDir(), Manifests: t.TempDir()}
	if err := st.Ensure(slot(t, certSpec)); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(st.Dir, boxsecrets.ValuesFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	known, err := st.Known()
	if err != nil {
		t.Fatal(err)
	}
	key := readStack(t, st.Manifests)["sneakers/sneakers-pgha-tls"].StringData["tls.key"]
	if !slices.Contains(known, key) {
		t.Fatal("the support bundle doesn't know to mask the private key")
	}
}
