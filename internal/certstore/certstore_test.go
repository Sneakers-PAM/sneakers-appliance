// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package certstore_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
)

const host = "box1.sneakers.example.org"

var addrs = []string{"192.0.2.10"}

type memSealer struct {
	mu    sync.Mutex
	items map[string][]byte
}

func (m *memSealer) Seal(name string, secret []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[name] = slices.Clone(secret)
	return nil
}

func (m *memSealer) Unseal(name string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.items[name]
	return slices.Clone(b), ok, nil
}

type fixture struct {
	t      *testing.T
	s      *certstore.Store
	sealer *memSealer
	dir    string
	admin  string
	ca     *testpki.TLSCA
	// probe decides whether the new certificate "serves".
	probeErr error
	probed   []string
	host     string
	addrs    []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureFor(t, host)
}

func newFixtureFor(t *testing.T, hostname string) *fixture {
	t.Helper()
	return newFixtureWith(t, hostname, addrs)
}

// newFixtureWith gives the store mgmt as netd's management addresses.
func newFixtureWith(t *testing.T, hostname string, mgmt []string) *fixture {
	t.Helper()
	f := &fixture{t: t, sealer: &memSealer{items: map[string][]byte{}}, dir: t.TempDir(), admin: t.TempDir(), ca: testpki.NewTLSCA(t), host: hostname, addrs: mgmt}
	// The box's own self-signed certificate, as sneakers-osadmin makes it.
	crt, key, err := certstore.NewSelfSigned(hostname, addrs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.write("tls.crt", crt)
	f.write("tls.key", key)
	f.s, err = certstore.Open(certstore.Options{
		Dir: f.dir, AdminDir: f.admin, Sealer: f.sealer,
		Names: func(context.Context) (string, []string, error) { return f.host, f.addrs, nil },
		Probe: func(_ context.Context, fp string) error {
			f.probed = append(f.probed, fp)
			return f.probeErr
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) write(name string, b []byte) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.admin, name), b, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) read(name string) []byte {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.admin, name)) // #nosec G304 -- the test's temp dir
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

func (f *fixture) chain() string { return string(f.ca.IntermediatePEM) + string(f.ca.RootPEM) }

func wantCode(t *testing.T, err error, code int, contains string) {
	t.Helper()
	if !codes.Is(err, code) {
		t.Fatalf("want %s, got %v", codes.Symbol(code), err)
	}
	if contains != "" && !strings.Contains(err.Error(), contains) {
		t.Fatalf("want %q in %v", contains, err)
	}
}

func checksOf(err error) []certstore.Check {
	var ve *certstore.ValidationError
	if errors.As(err, &ve) {
		return ve.Checks
	}
	return nil
}

func TestTheSelfSignedCertificateIsListedAndServesTheAdminEndpoint(t *testing.T) {
	f := newFixture(t)
	snap, err := f.s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Certificates) != 1 || snap.Certificates[0].Source != certstore.SourceSelfSigned || !slices.Equal(snap.Certificates[0].UsedBy, []string{certstore.EndpointAdmin}) {
		t.Fatalf("%+v", snap.Certificates)
	}
	admin, product := snap.Endpoints[0], snap.Endpoints[1]
	if admin.ID != certstore.EndpointAdmin || !admin.Available || admin.Source != certstore.EndpointSelfSigned || admin.State != certstore.StateSelfSigned {
		t.Fatalf("%+v", admin)
	}
	if product.ID != certstore.EndpointProduct || product.Available || product.Reason != "Available when the product is installed." {
		t.Fatalf("%+v", product)
	}
	if snap.ACME.Available || snap.ACME.Reason == "" {
		t.Fatalf("%+v", snap.ACME)
	}
}

func TestACSRKeyIsSealedAndItsCertificateIsStored(t *testing.T) {
	f := newFixture(t)
	csr, err := f.s.GenerateCSR(context.Background(), certstore.CSRRequest{Names: []string{"admin.sneakers.example.org"}, Organization: "Example"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{host, "admin.sneakers.example.org", "192.0.2.10"}
	if !slices.Equal(csr.Names, want) || csr.KeyType != "RSA 4096" {
		t.Fatalf("%+v", csr)
	}
	blk, _ := pem.Decode([]byte(csr.PEM))
	req, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || req.CheckSignature() != nil || req.Subject.CommonName != host || req.Subject.Organization[0] != "Example" {
		t.Fatalf("%v %+v", err, req.Subject)
	}
	if k := f.sealer.items["tls-"+csr.ID]; !bytes.Contains(k, []byte("PRIVATE KEY")) {
		t.Fatal("the CSR's key is sealed")
	}
	stored, err := os.ReadFile(filepath.Join(f.dir, "store.json")) // #nosec G304 -- the test's temp dir
	if err != nil || bytes.Contains(stored, []byte("PRIVATE KEY")) {
		t.Fatal("the store file holds no key")
	}

	leaf := f.ca.SignCSR(t, []byte(csr.PEM), testpki.LeafOptions{})
	c, checks, err := f.s.CompleteCSR(context.Background(), csr.ID, string(leaf.PEM), f.chain(), "")
	if err != nil {
		t.Fatal(err)
	}
	if c.Source != certstore.SourceCSRSigned || c.CSRID != csr.ID || len(c.Chain) != 3 || len(c.UsedBy) != 0 {
		t.Fatalf("%+v", c)
	}
	for _, ch := range checks {
		if !ch.Passed {
			t.Fatalf("%+v", checks)
		}
	}
	snap, _ := f.s.Snapshot(context.Background())
	if len(snap.CSRs) != 0 || len(snap.Certificates) != 2 {
		t.Fatalf("the CSR is completed: %+v", snap.CSRs)
	}
}

func TestTheOtherCSRKeyTypes(t *testing.T) {
	f := newFixture(t)
	for kt, want := range map[certstore.KeyType]string{
		certstore.KeyRSA3072: "RSA 3072", certstore.KeyECDSAP256: "ECDSA P-256", certstore.KeyECDSAP384: "ECDSA P-384",
	} {
		csr, err := f.s.GenerateCSR(context.Background(), certstore.CSRRequest{KeyType: kt})
		if err != nil || csr.KeyType != want {
			t.Fatalf("%+v %v", csr, err)
		}
	}
}

func TestAnRSAKeyUnder3072BitsIsRefused(t *testing.T) {
	f := newFixture(t)
	weak, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}, Public: &weak.PublicKey})
	der, err := x509.MarshalPKCS8PrivateKey(weak)
	if err != nil {
		t.Fatal(err)
	}
	kp := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	_, _, err = f.s.Import(context.Background(), certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: f.chain(), KeyPEM: string(kp)})
	wantCode(t, err, codes.TLSKeyType, "3072")
}

func TestAWildcardCoversOneLabel(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	wild := f.ca.Issue(t, testpki.LeafOptions{Names: []string{"*.sneakers.example.org"}})
	c, _, err := f.s.Import(ctx, certstore.ImportRequest{CertificatePEM: string(wild.PEM), ChainPEM: f.chain(), KeyPEM: string(wild.KeyPEM)})
	if err != nil {
		t.Fatalf("*.sneakers.example.org covers %s: %v", host, err)
	}
	if _, err := f.s.Assign(ctx, certstore.EndpointAdmin, c.ID); err != nil {
		t.Fatal(err)
	}

	twoLabels := f.ca.Issue(t, testpki.LeafOptions{Names: []string{"*.example.org"}})
	_, _, err = f.s.Import(ctx, certstore.ImportRequest{CertificatePEM: string(twoLabels.PEM), ChainPEM: f.chain(), KeyPEM: string(twoLabels.KeyPEM)})
	wantCode(t, err, codes.TLSNames, "*.example.org")

	bare := newFixtureFor(t, "sneakers.example.org")
	l := bare.ca.Issue(t, testpki.LeafOptions{Names: []string{"*.sneakers.example.org"}})
	_, _, err = bare.s.Import(ctx, certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: bare.chain(), KeyPEM: string(l.KeyPEM)})
	wantCode(t, err, codes.TLSNames, "sneakers.example.org")
}

func TestACSRIsForOneNameAndNeverAWildcard(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, n := range []string{"*.sneakers.example.org", "*", "*.org", "b*.example.org"} {
		_, err := f.s.GenerateCSR(ctx, certstore.CSRRequest{Names: []string{n}, KeyType: certstore.KeyECDSAP256})
		wantCode(t, err, codes.TLSInvalid, "")
	}
	_, err := f.s.GenerateCSR(ctx, certstore.CSRRequest{Names: []string{"*.sneakers.example.org"}, KeyType: certstore.KeyECDSAP256})
	wantCode(t, err, codes.TLSInvalid, "a wildcard key is shared across servers; import it with Upload PFX")
	_, err = f.s.GenerateCSR(ctx, certstore.CSRRequest{Names: []string{"a.sneakers.example.org", "b.sneakers.example.org"}, KeyType: certstore.KeyECDSAP256})
	wantCode(t, err, codes.TLSInvalid, "one name")
	csr, err := f.s.GenerateCSR(ctx, certstore.CSRRequest{Names: []string{"a.sneakers.example.org", host, "192.0.2.10"}, KeyType: certstore.KeyECDSAP256})
	if err != nil || len(csr.Names) != 3 {
		t.Fatalf("the box's own names don't count as the one name: %+v %v", csr, err)
	}
}

func TestAPFXWithAWildcardAndItsFullChainIsImportedAndServes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{"*.sneakers.example.org"}})
	p12, err := pkcs12.Modern.Encode(l.Key, l.Cert, []*x509.Certificate{f.ca.Intermediate, f.ca.Root}, "test-only-password")
	if err != nil {
		t.Fatal(err)
	}
	c, checks, err := f.s.Import(ctx, certstore.ImportRequest{PKCS12: p12, PKCS12Password: "test-only-password"})
	if err != nil || len(c.Chain) != 3 || len(checks) != 5 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := f.s.Assign(ctx, certstore.EndpointAdmin, c.ID); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(f.read("tls.crt"), l.PEM) {
		t.Fatal("the wildcard serves :8443")
	}
}

func TestAPFXWithAnIncompleteChainIsRefused(t *testing.T) {
	f := newFixture(t)
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}})
	p12, err := pkcs12.Modern.Encode(l.Key, l.Cert, []*x509.Certificate{f.ca.Root}, "test-only-password")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = f.s.Import(context.Background(), certstore.ImportRequest{PKCS12: p12, PKCS12Password: "test-only-password"})
	wantCode(t, err, codes.TLSChain, f.ca.Intermediate.Subject.CommonName)
}

func TestAPFXWithAnRSA2048KeyIsRefused(t *testing.T) {
	f := newFixture(t)
	weak, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}, Public: &weak.PublicKey})
	p12, err := pkcs12.Modern.Encode(weak, l.Cert, []*x509.Certificate{f.ca.Intermediate, f.ca.Root}, "test-only-password")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = f.s.Import(context.Background(), certstore.ImportRequest{PKCS12: p12, PKCS12Password: "test-only-password"})
	wantCode(t, err, codes.TLSKeyType, "3072")
}

func TestACSRRequestIsValidated(t *testing.T) {
	f := newFixture(t)
	for _, r := range []certstore.CSRRequest{
		{Names: []string{"not a name"}},
		{Names: []string{"-bad.example.org"}},
		{Country: "USA"},
	} {
		_, err := f.s.GenerateCSR(context.Background(), r)
		wantCode(t, err, codes.TLSInvalid, "")
	}
	for range 8 {
		if _, err := f.s.GenerateCSR(context.Background(), certstore.CSRRequest{KeyType: certstore.KeyECDSAP256}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := f.s.GenerateCSR(context.Background(), certstore.CSRRequest{KeyType: certstore.KeyECDSAP256})
	wantCode(t, err, codes.TLSLimit, "")
}

func TestAWrongKeyIsRefused(t *testing.T) {
	f := newFixture(t)
	csr, err := f.s.GenerateCSR(context.Background(), certstore.CSRRequest{})
	if err != nil {
		t.Fatal(err)
	}
	other := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}})
	_, _, err = f.s.CompleteCSR(context.Background(), csr.ID, string(other.PEM), f.chain(), "")
	wantCode(t, err, codes.TLSKeyMismatch, csr.ID)
	if c := checksOf(err); len(c) == 0 || c[0].Name != "key" || c[0].Passed {
		t.Fatalf("%+v", c)
	}

	a := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}})
	b := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}})
	_, _, err = f.s.Import(context.Background(), certstore.ImportRequest{CertificatePEM: string(a.PEM), ChainPEM: f.chain(), KeyPEM: string(b.KeyPEM)})
	wantCode(t, err, codes.TLSKeyMismatch, "")
	snap, _ := f.s.Snapshot(context.Background())
	if len(snap.Certificates) != 1 {
		t.Fatal("nothing is stored on a failure")
	}
}

func TestAWrongSANIsRefused(t *testing.T) {
	f := newFixture(t)
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{"www.example.org"}})
	_, _, err := f.s.Import(context.Background(), certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: f.chain(), KeyPEM: string(l.KeyPEM)})
	wantCode(t, err, codes.TLSNames, "www.example.org")
}

func TestAnExpiredOrNotYetValidCertificateIsRefused(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	old := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}, NotBefore: now.Add(-20 * 24 * time.Hour), NotAfter: now.Add(-24 * time.Hour)})
	_, _, err := f.s.Import(context.Background(), certstore.ImportRequest{CertificatePEM: string(old.PEM), ChainPEM: f.chain(), KeyPEM: string(old.KeyPEM)})
	wantCode(t, err, codes.TLSValidity, "expired on")
	early := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}, NotBefore: now.Add(48 * time.Hour)})
	_, _, err = f.s.Import(context.Background(), certstore.ImportRequest{CertificatePEM: string(early.PEM), ChainPEM: f.chain(), KeyPEM: string(early.KeyPEM)})
	wantCode(t, err, codes.TLSValidity, "not valid until")
}

func TestAMissingIntermediateIsNamed(t *testing.T) {
	f := newFixture(t)
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}})
	_, _, err := f.s.Import(context.Background(), certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: string(f.ca.RootPEM), KeyPEM: string(l.KeyPEM)})
	wantCode(t, err, codes.TLSChain, f.ca.Intermediate.Subject.CommonName)

	// The chain without its root, and the root uploaded on its own.
	_, _, err = f.s.Import(context.Background(), certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: string(f.ca.IntermediatePEM), KeyPEM: string(l.KeyPEM)})
	wantCode(t, err, codes.TLSChain, f.ca.Root.Subject.CommonName)
	c, _, err := f.s.Import(context.Background(), certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: string(f.ca.IntermediatePEM), KeyPEM: string(l.KeyPEM), RootPEM: string(f.ca.RootPEM)})
	if err != nil || c.Source != certstore.SourceUploaded || len(c.Chain) != 3 {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestACACertificateOrAClientCertificateIsRefused(t *testing.T) {
	f := newFixture(t)
	ca := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}, IsCA: true})
	_, _, err := f.s.Import(context.Background(), certstore.ImportRequest{CertificatePEM: string(ca.PEM), ChainPEM: f.chain(), KeyPEM: string(ca.KeyPEM)})
	wantCode(t, err, codes.TLSUsage, "")
	client := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	_, _, err = f.s.Import(context.Background(), certstore.ImportRequest{CertificatePEM: string(client.PEM), ChainPEM: f.chain(), KeyPEM: string(client.KeyPEM)})
	wantCode(t, err, codes.TLSUsage, "")
}

func TestPKCS12IsImportedAndNeverKept(t *testing.T) {
	f := newFixture(t)
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host, "192.0.2.10"}})
	p12, err := pkcs12.Modern.Encode(l.Key, l.Cert, []*x509.Certificate{f.ca.Intermediate, f.ca.Root}, "test-only-password")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = f.s.Import(context.Background(), certstore.ImportRequest{PKCS12: p12, PKCS12Password: "wrong"})
	wantCode(t, err, codes.TLSFormat, "password")
	c, _, err := f.s.Import(context.Background(), certstore.ImportRequest{PKCS12: p12, PKCS12Password: "test-only-password"})
	if err != nil || c.Source != certstore.SourceUploaded || len(c.Chain) != 3 {
		t.Fatalf("%+v %v", c, err)
	}
	stored, _ := os.ReadFile(filepath.Join(f.dir, "store.json")) // #nosec G304 -- the test's temp dir
	if bytes.Contains(stored, p12) || bytes.Contains(stored, []byte("PRIVATE KEY")) {
		t.Fatal("the PKCS#12 and the key aren't in the store file")
	}
}

func TestAssigningSwapsTheAdminFilesAndReverting(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	selfCrt := f.read("tls.crt")
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}})
	c, _, err := f.s.Import(context.Background(), certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: f.chain(), KeyPEM: string(l.KeyPEM)})
	if err != nil {
		t.Fatal(err)
	}
	ep, err := f.s.Assign(ctx, certstore.EndpointAdmin, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ep.Source != certstore.EndpointAssigned || ep.CertificateID != c.ID || ep.State != certstore.StateOK || ep.Serving != c.Fingerprint {
		t.Fatalf("%+v", ep)
	}
	if !bytes.HasPrefix(f.read("tls.crt"), l.PEM) || string(f.read("tls.assigned")) != c.ID+"\n" {
		t.Fatal("the admin files carry the assigned certificate and its marker")
	}
	if !slices.Equal(f.probed, []string{c.Fingerprint}) {
		t.Fatalf("probed %v", f.probed)
	}
	if err := f.s.Delete(c.ID); !codes.Is(err, codes.TLSInUse) {
		t.Fatalf("in use: %v", err)
	}

	ep, err = f.s.Revert(ctx, certstore.EndpointAdmin)
	if err != nil || ep.Source != certstore.EndpointSelfSigned {
		t.Fatalf("%+v %v", ep, err)
	}
	if !bytes.Equal(f.read("tls.crt"), selfCrt) {
		t.Fatal("the earlier self-signed certificate is back")
	}
	if _, err := os.Stat(filepath.Join(f.admin, "tls.assigned")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the marker is gone")
	}
	if err := f.s.Delete(c.ID); err != nil {
		t.Fatal(err)
	}
	snap, _ := f.s.Snapshot(ctx)
	if len(snap.Certificates) != 1 {
		t.Fatal("deleted")
	}
	if err := f.s.Delete(snap.Certificates[0].ID); !codes.Is(err, codes.TLSInUse) {
		t.Fatalf("the self-signed one isn't deleted: %v", err)
	}
}

func TestACertificateThatIsNotServedIsRolledBack(t *testing.T) {
	f := newFixture(t)
	before := f.read("tls.crt")
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}})
	c, _, err := f.s.Import(context.Background(), certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: f.chain(), KeyPEM: string(l.KeyPEM)})
	if err != nil {
		t.Fatal(err)
	}
	f.probeErr = errors.New("the handshake served the old certificate")
	_, err = f.s.Assign(context.Background(), certstore.EndpointAdmin, c.ID)
	wantCode(t, err, codes.TLSNotServed, "put back")
	if !bytes.Equal(f.read("tls.crt"), before) {
		t.Fatal("the previous certificate is back")
	}
	if _, err := os.Stat(filepath.Join(f.admin, "tls.assigned")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("no marker after a rollback to self-signed")
	}
	snap, _ := f.s.Snapshot(context.Background())
	if snap.Endpoints[0].Source != certstore.EndpointSelfSigned {
		t.Fatalf("%+v", snap.Endpoints[0])
	}
}

func TestAssigningChecksTheEndpoint(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}})
	c, _, err := f.s.Import(context.Background(), certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: f.chain(), KeyPEM: string(l.KeyPEM)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.s.Assign(ctx, certstore.EndpointProduct, c.ID)
	wantCode(t, err, codes.TLSEndpointUnavailable, "")
	_, err = f.s.Assign(ctx, "nope", c.ID)
	wantCode(t, err, codes.TLSUnknown, "")
	_, err = f.s.Assign(ctx, certstore.EndpointAdmin, "nope")
	wantCode(t, err, codes.TLSUnknown, "")
}

func TestExpiryIsShownOnTheEndpoint(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}, NotAfter: time.Now().Add(12 * 24 * time.Hour)})
	c, _, err := f.s.Import(context.Background(), certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: f.chain(), KeyPEM: string(l.KeyPEM)})
	if err != nil {
		t.Fatal(err)
	}
	ep, err := f.s.Assign(ctx, certstore.EndpointAdmin, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ep.State != certstore.StateExpiring || !strings.Contains(ep.Detail, "expires in 11 days") && !strings.Contains(ep.Detail, "expires in 12 days") {
		t.Fatalf("%+v", ep)
	}
}

func TestTheStoreSurvivesAReopen(t *testing.T) {
	f := newFixture(t)
	csr, err := f.s.GenerateCSR(context.Background(), certstore.CSRRequest{})
	if err != nil {
		t.Fatal(err)
	}
	s2, err := certstore.Open(certstore.Options{Dir: f.dir, AdminDir: f.admin, Sealer: f.sealer,
		Names: func(context.Context) (string, []string, error) { return host, addrs, nil }})
	if err != nil {
		t.Fatal(err)
	}
	leaf := f.ca.SignCSR(t, []byte(csr.PEM), testpki.LeafOptions{})
	if _, _, err := s2.CompleteCSR(context.Background(), csr.ID, string(leaf.PEM), f.chain(), ""); err != nil {
		t.Fatal(err)
	}
	if err := s2.DiscardCSR("nope"); !codes.Is(err, codes.TLSUnknown) {
		t.Fatal(err)
	}
}

// netd gives the management addresses as interface prefixes.
var prefixed = []string{"192.0.2.10/24", "fe80::10/64"}

func TestInterfacePrefixesBecomeBareAddressesInTheBoxNames(t *testing.T) {
	f := newFixtureWith(t, host, prefixed)
	ctx := context.Background()
	csr, err := f.s.GenerateCSR(ctx, certstore.CSRRequest{KeyType: certstore.KeyECDSAP256})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(csr.Names, []string{host, "192.0.2.10"}) {
		t.Fatalf("names %v", csr.Names)
	}
	blk, _ := pem.Decode([]byte(csr.PEM))
	req, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || len(req.IPAddresses) != 1 || req.IPAddresses[0].String() != "192.0.2.10" {
		t.Fatalf("IP SANs %v %v", req.IPAddresses, err)
	}
	snap, err := f.s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := snap.Endpoints[0].Names; !slices.Equal(got, []string{host, "192.0.2.10"}) {
		t.Fatalf("endpoint names %v", got)
	}

	ipOnly := f.ca.Issue(t, testpki.LeafOptions{Names: []string{"192.0.2.10"}})
	c, _, err := f.s.Import(ctx, certstore.ImportRequest{CertificatePEM: string(ipOnly.PEM), ChainPEM: f.chain(), KeyPEM: string(ipOnly.KeyPEM)})
	if err != nil {
		t.Fatalf("a certificate for the bare address covers the box: %v", err)
	}
	if _, err := f.s.Assign(ctx, certstore.EndpointAdmin, c.ID); err != nil {
		t.Fatal(err)
	}
}

func TestRevertingWithPrefixedAddressesPutsBackTheSameSelfSignedCertificate(t *testing.T) {
	f := newFixtureWith(t, host, prefixed)
	ctx := context.Background()
	selfCrt := f.read("tls.crt")
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}})
	c, _, err := f.s.Import(ctx, certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: f.chain(), KeyPEM: string(l.KeyPEM)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Assign(ctx, certstore.EndpointAdmin, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Revert(ctx, certstore.EndpointAdmin); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.read("tls.crt"), selfCrt) {
		t.Fatal("the recorded self-signed certificate is put back, not a new one")
	}
}

// serveAdmin is :8443 on the loopback: each handshake serves the admin
// directory's current files, as sneakers-osadmin does.
func serveAdmin(t *testing.T, dir string) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
		return &c, err
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.(*tls.Conn).Handshake()
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return port
}

func TestTheDefaultProbeDialsTheBareManagementAddress(t *testing.T) {
	admin := t.TempDir()
	crt, key, err := certstore.NewSelfSigned(host, []string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"tls.crt": crt, "tls.key": key} {
		if err := os.WriteFile(filepath.Join(admin, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	certstore.SetProbePort(t, serveAdmin(t, admin))
	s, err := certstore.Open(certstore.Options{
		Dir: t.TempDir(), AdminDir: admin, Sealer: &memSealer{items: map[string][]byte{}},
		Names: func(context.Context) (string, []string, error) { return host, []string{"127.0.0.1/8"}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ca := testpki.NewTLSCA(t)
	ctx := context.Background()
	l := ca.Issue(t, testpki.LeafOptions{Names: []string{host}})
	c, _, err := s.Import(ctx, certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: string(ca.IntermediatePEM) + string(ca.RootPEM), KeyPEM: string(l.KeyPEM)})
	if err != nil {
		t.Fatal(err)
	}
	ep, err := s.Assign(ctx, certstore.EndpointAdmin, c.ID)
	if err != nil {
		t.Fatalf("the probe reaches 127.0.0.1, not 127.0.0.1/8: %v", err)
	}
	if ep.Serving != c.Fingerprint {
		t.Fatalf("%+v", ep)
	}
}

func TestTheStoreAnswersWhileANewCertificateIsBeingChecked(t *testing.T) {
	for _, served := range []bool{false, true} {
		f := newFixture(t)
		ctx := context.Background()
		before := f.read("tls.crt")
		probing, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		f.s = reopen(t, f, func(context.Context, string) error {
			once.Do(func() { close(probing) })
			<-release
			if served {
				return nil
			}
			return errors.New("the handshake served the old certificate")
		})
		l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}})
		c, _, err := f.s.Import(ctx, certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: f.chain(), KeyPEM: string(l.KeyPEM)})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := f.s.Assign(ctx, certstore.EndpointAdmin, c.ID)
			done <- err
		}()
		<-probing
		snapped := make(chan certstore.Snapshot, 1)
		go func() {
			snap, _ := f.s.Snapshot(ctx)
			snapped <- snap
		}()
		select {
		case snap := <-snapped:
			if snap.Endpoints[0].Source != certstore.EndpointSelfSigned {
				t.Fatalf("nothing is assigned until the check passes: %+v", snap.Endpoints[0])
			}
			if self := snap.Certificates[0]; self.Source != certstore.SourceSelfSigned || self.Fingerprint == c.Fingerprint {
				t.Fatalf("the certificate being checked isn't recorded as the self-signed one: %+v", self)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Snapshot waits for the :8443 check")
		}
		close(release)
		err = <-done
		snap, _ := f.s.Snapshot(ctx)
		if served {
			if err != nil || snap.Endpoints[0].CertificateID != c.ID {
				t.Fatalf("%v %+v", err, snap.Endpoints[0])
			}
			continue
		}
		wantCode(t, err, codes.TLSNotServed, "put back")
		if !bytes.Equal(f.read("tls.crt"), before) || snap.Certificates[0].Fingerprint == c.Fingerprint {
			t.Fatal("the previous certificate is back and still recorded as the self-signed one")
		}
	}
}

// reopen opens f's store again with probe as its :8443 check.
func reopen(t *testing.T, f *fixture, probe func(context.Context, string) error) *certstore.Store {
	t.Helper()
	s, err := certstore.Open(certstore.Options{Dir: f.dir, AdminDir: f.admin, Sealer: f.sealer,
		Names: func(context.Context) (string, []string, error) { return f.host, f.addrs, nil }, Probe: probe})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The self-signed certificate names the product as it's written
// everywhere else: "Sneakers-PAM Appliance".
func TestTheSelfSignedCertificateNamesTheAppliance(t *testing.T) {
	crt, _, err := certstore.NewSelfSigned(host, addrs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(crt)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Subject.Organization; len(got) != 1 || got[0] != "Sneakers-PAM Appliance admin" {
		t.Fatalf("organization %q", got)
	}
}

func TestAWildcardPFXIsRefusedUntilTheBoxHasAHostNameAndThenCoversItWithoutTheAddress(t *testing.T) {
	f := newFixtureFor(t, "")
	ctx := context.Background()
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{"*.example.org"}})
	p12, err := pkcs12.Modern.Encode(l.Key, l.Cert, []*x509.Certificate{f.ca.Intermediate, f.ca.Root}, "test-only-password")
	if err != nil {
		t.Fatal(err)
	}
	req := certstore.ImportRequest{PKCS12: p12, PKCS12Password: "test-only-password"}
	_, _, err = f.s.Import(ctx, req)
	wantCode(t, err, codes.TLSNoHostname, "this box has no host name yet, so the certificate is checked against 192.0.2.10 only")
	for _, want := range []string{"*.example.org", "set the host name on Network"} {
		wantCode(t, err, codes.TLSNoHostname, want)
	}

	f.host = "appliance.example.org"
	c, checks, err := f.s.Import(ctx, req)
	if err != nil {
		t.Fatalf("*.example.org covers appliance.example.org, and the address isn't needed: %v", err)
	}
	for _, ch := range checks {
		if ch.Name == "names" && ch.Detail != "covers appliance.example.org" {
			t.Fatalf("names check: %+v", ch)
		}
	}
	if _, err := f.s.Assign(ctx, certstore.EndpointAdmin, c.ID); err != nil {
		t.Fatal(err)
	}

	f.host = ""
	if _, err := f.s.Revert(ctx, certstore.EndpointAdmin); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.Assign(ctx, certstore.EndpointAdmin, c.ID)
	wantCode(t, err, codes.TLSNoHostname, "192.0.2.10")
}

func TestANamesRefusalSaysWhichNamesWereCheckedAndWhichTheCertificateCovers(t *testing.T) {
	f := newFixture(t)
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{"www.example.org", "mail.example.org"}})
	_, _, err := f.s.Import(context.Background(), certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: f.chain(), KeyPEM: string(l.KeyPEM)})
	wantCode(t, err, codes.TLSNames, "the certificate covers www.example.org, mail.example.org, but none of the names this box checks: "+host+", 192.0.2.10")
}

// An assigned certificate stays assigned across a reboot, an update and a
// revert: each opens the store again from the state volume.
func TestAnAssignmentSurvivesAReopen(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}})
	c, _, err := f.s.Import(ctx, certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: f.chain(), KeyPEM: string(l.KeyPEM)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Assign(ctx, certstore.EndpointAdmin, c.ID); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		s2, err := certstore.Open(certstore.Options{Dir: f.dir, AdminDir: f.admin, Sealer: f.sealer,
			Names: func(context.Context) (string, []string, error) { return host, addrs, nil }})
		if err != nil {
			t.Fatal(err)
		}
		snap, err := s2.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ep := snap.Endpoints[0]; ep.Source != certstore.EndpointAssigned || ep.CertificateID != c.ID {
			t.Fatalf("after a reopen %+v", ep)
		}
		if certstore.AssignedID(f.admin) != c.ID {
			t.Fatal("the admin directory's marker is gone")
		}
	}
}

// A box with no host name from the settings or DHCP still names itself in
// a CSR: its own name (sneakers-<8 hex>), the name the console shows.
func TestACSRCarriesTheBoxsOwnNameWithoutAHostName(t *testing.T) {
	f := newFixtureWith(t, "", []string{"192.0.2.10/24"})
	f.s.SetOwnName(func() string { return "sneakers-62f51517" })
	csr, err := f.s.GenerateCSR(context.Background(), certstore.CSRRequest{KeyType: certstore.KeyECDSAP256})
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(csr.PEM))
	req, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(req.DNSNames, []string{"sneakers-62f51517"}) || len(req.IPAddresses) != 1 || req.Subject.CommonName != "sneakers-62f51517" {
		t.Fatalf("SANs %v %v CN %q", req.DNSNames, req.IPAddresses, req.Subject.CommonName)
	}
	// With a host name, that's the name; the box's own name isn't added.
	g := newFixtureWith(t, host, []string{"192.0.2.10/24"})
	g.s.SetOwnName(func() string { return "sneakers-62f51517" })
	csr, err = g.s.GenerateCSR(context.Background(), certstore.CSRRequest{KeyType: certstore.KeyECDSAP256})
	if err != nil || slices.Contains(csr.Names, "sneakers-62f51517") || !slices.Contains(csr.Names, host) {
		t.Fatalf("%v %v", csr.Names, err)
	}
}
