// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
)

const boxHost = "box1.sneakers.example.org"

// certBox is a box whose :8443 is a real TLS listener on the loopback,
// served from the admin directory the store swaps.
type certBox struct {
	*box
	ca       *testpki.TLSCA
	adminDir string
	addr     string
	sealer   *memSealer
}

// newCertBox starts it; staticProbe points the store's self-test at a
// listener that never changes its certificate, so every swap rolls back.
func newCertBox(t *testing.T, withBob, staticProbe bool) *certBox {
	t.Helper()
	cb := &certBox{ca: testpki.NewTLSCA(t), sealer: newMemSealer()}
	cb.box = newBox(t, withBob, func(b *box, o *osadmin.Options) {
		cb.adminDir = filepath.Join(b.state, "osadmin")
		c, _, err := osadmin.EnsureCert(cb.adminDir, boxHost, []string{"192.0.2.10"}, b.clk.Now())
		if err != nil {
			t.Fatal(err)
		}
		cb.addr = serveTLS(t, osadmin.NewCertSource(cb.adminDir, c, nil).GetCertificate)
		probeAddr := cb.addr
		if staticProbe {
			probeAddr = serveTLS(t, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &c, nil })
		}
		host, port, _ := net.SplitHostPort(probeAddr)
		store, err := certstore.Open(certstore.Options{
			Dir: filepath.Join(b.state, "osadmin-api", "tls"), AdminDir: cb.adminDir, Sealer: cb.sealer, Now: b.clk.Now,
			Names: func(context.Context) (string, []string, error) {
				b.netd.mu.Lock()
				defer b.netd.mu.Unlock()
				return boxHost, slices.Clone(b.netd.mgmt), nil
			},
			Probe: func(ctx context.Context, fp string) error {
				pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				return certstore.HandshakeProbe(pctx, []string{host}, port, fp)
			},
			Logger: log.Nop(),
		})
		if err != nil {
			t.Fatal(err)
		}
		o.Certs, o.CertDir = store, cb.adminDir
	})
	return cb
}

func serveTLS(t *testing.T, get func(*tls.ClientHelloInfo) (*tls.Certificate, error)) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: get, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.NotFoundHandler(), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// served is the fingerprint a handshake to addr gets.
func served(t *testing.T, addr string) string {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // #nosec G402 -- the test compares fingerprints
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return osadmin.Fingerprint(c.ConnectionState().PeerCertificates[0].Raw)
}

func (br *browser) tls() osadminv1connect.TlsServiceClient {
	return osadminv1connect.NewTlsServiceClient(br.hc, br.b.ts.URL)
}

func (cb *certBox) chain() string { return string(cb.ca.IntermediatePEM) + string(cb.ca.RootPEM) }

func (cb *certBox) leaf(t *testing.T, names ...string) testpki.Leaf {
	t.Helper()
	return cb.ca.Issue(t, testpki.LeafOptions{Names: names, NotBefore: cb.clk.Now().Add(-time.Hour)})
}

func TestTheCSRFlowSwapsThe8443CertificateLive(t *testing.T) {
	cb := newCertBox(t, false, false)
	br := cb.browser()
	br.signIn("alice")
	ctx := context.Background()
	before := served(t, cb.addr)

	gen, err := br.tls().GenerateCsr(ctx, connect.NewRequest(&osadminv1.GenerateCsrRequest{Names: []string{"admin.sneakers.example.org"}, KeyType: osadminv1.KeyType_KEY_TYPE_ECDSA_P256}))
	if err != nil {
		t.Fatal(err)
	}
	csr := gen.Msg.GetCsr()
	if !slices.Contains(csr.GetNames(), boxHost) || !slices.Contains(csr.GetNames(), "192.0.2.10") || !strings.HasPrefix(csr.GetCsrPem(), "-----BEGIN CERTIFICATE REQUEST-----") {
		t.Fatalf("%+v", csr)
	}
	leaf := cb.ca.SignCSR(t, []byte(csr.GetCsrPem()), testpki.LeafOptions{NotBefore: cb.clk.Now().Add(-time.Hour)})
	done, err := br.tls().CompleteCsr(ctx, connect.NewRequest(&osadminv1.CompleteCsrRequest{CsrId: csr.GetId(), CertificatePem: string(leaf.PEM), ChainPem: cb.chain()}))
	if err != nil {
		t.Fatal(err)
	}
	cert := done.Msg.GetCertificate()
	if cert.GetSource() != osadminv1.CertificateSource_CERTIFICATE_SOURCE_CSR_SIGNED || len(done.Msg.GetChecks()) != 5 {
		t.Fatalf("%+v", done.Msg)
	}

	as, err := br.tls().AssignCertificate(ctx, connect.NewRequest(&osadminv1.AssignCertificateRequest{EndpointId: "admin", CertificateId: cert.GetId()}))
	if err != nil {
		t.Fatal(err)
	}
	if as.Msg.GetEndpoint().GetState() != osadminv1.EndpointState_ENDPOINT_STATE_OK || as.Msg.GetEndpoint().GetServingFingerprint() != cert.GetFingerprint() {
		t.Fatalf("%+v", as.Msg.GetEndpoint())
	}
	if got := served(t, cb.addr); got != cert.GetFingerprint() {
		t.Fatalf(":8443 serves %s, want %s", got, cert.GetFingerprint())
	}
	st, err := osadminv1connect.NewStatusServiceClient(br.hc, cb.ts.URL).GetStatus(ctx, connect.NewRequest(&osadminv1.GetStatusRequest{}))
	if err != nil || st.Msg.GetTlsFingerprint() != cert.GetFingerprint() || st.Msg.GetTlsSelfSigned() {
		t.Fatalf("Status follows the swap: %v %v", st, err)
	}
	e := lastEntry(t, cb.log, "tls.endpoint.assign")
	if e.Outcome != "ok" || e.Target != "admin" || e.Detail["fingerprint"] != cert.GetFingerprint() || e.Detail["source"] != "csr-signed" {
		t.Fatalf("%+v", e)
	}
	for _, action := range []string{"tls.csr.generate", "tls.csr.complete"} {
		if lastEntry(t, cb.log, action).Outcome != "ok" {
			t.Fatal(action)
		}
	}

	if _, err := br.tls().RevertToSelfSigned(ctx, connect.NewRequest(&osadminv1.RevertToSelfSignedRequest{EndpointId: "admin"})); err != nil {
		t.Fatal(err)
	}
	if got := served(t, cb.addr); got != before {
		t.Fatalf("reverted: %s, want %s", got, before)
	}
	got, err := br.tls().GetCertificateStore(ctx, connect.NewRequest(&osadminv1.GetCertificateStoreRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Msg.GetCertificates()) != 2 || got.Msg.GetEndpoints()[0].GetSource() != osadminv1.EndpointSource_ENDPOINT_SOURCE_SELF_SIGNED || got.Msg.GetAcme().GetAvailable() {
		t.Fatalf("%+v", got.Msg)
	}
	if _, err := br.tls().DeleteCertificate(ctx, connect.NewRequest(&osadminv1.DeleteCertificateRequest{CertificateId: cert.GetId()})); err != nil {
		t.Fatal(err)
	}
	want := "certificate " + strings.Join(cert.GetNames(), ", ")
	if e := lastEntry(t, cb.log, "tls.certificate.delete"); e.Target != want || e.Detail["certificate"] != cert.GetId() || e.Detail["fingerprint"] != cert.GetFingerprint() {
		t.Fatalf("delete entry %+v, want target %q and the id and fingerprint in the detail", e, want)
	}
}

func TestCertificateChangesNeedAnOwnerAndAFreshSignIn(t *testing.T) {
	cb := newCertBox(t, true, false)
	ctx := context.Background()
	bob := cb.browser()
	bob.signIn("bob")
	if _, err := bob.tls().GetCertificateStore(ctx, connect.NewRequest(&osadminv1.GetCertificateStoreRequest{})); err != nil {
		t.Fatalf("an admin reads the store: %v", err)
	}
	_, err := bob.tls().GenerateCsr(ctx, connect.NewRequest(&osadminv1.GenerateCsrRequest{}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	if e := lastEntry(t, cb.log, "tls.csr.generate"); e.Outcome != "refused" || e.Actor != "bob" {
		t.Fatalf("%+v", e)
	}

	alice := cb.browser()
	alice.signIn("alice")
	cb.clk.Advance(6 * time.Minute)
	_, err = alice.tls().AssignCertificate(ctx, connect.NewRequest(&osadminv1.AssignCertificateRequest{}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_STEPUP_REQUIRED")
}

func TestARefusedUploadSaysWhyAndListsItsChecks(t *testing.T) {
	cb := newCertBox(t, false, false)
	br := cb.browser()
	br.signIn("alice")
	l := cb.leaf(t, "www.example.org")
	_, err := br.tls().ImportCertificate(context.Background(), connect.NewRequest(&osadminv1.ImportCertificateRequest{CertificatePem: string(l.PEM), ChainPem: cb.chain(), KeyPem: string(l.KeyPEM)}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "TLS_NAMES")
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatal(err)
	}
	var report *osadminv1.ValidationReport
	for _, d := range ce.Details() {
		if m, derr := d.Value(); derr == nil {
			if r, ok := m.(*osadminv1.ValidationReport); ok {
				report = r
			}
		}
	}
	if report == nil {
		t.Fatal("no ValidationReport detail")
	}
	failed := 0
	for _, c := range report.GetChecks() {
		if !c.GetPassed() {
			failed++
			if c.GetName() != "names" || !strings.Contains(c.GetDetail(), "www.example.org") {
				t.Fatalf("%+v", c)
			}
		}
	}
	if failed != 1 {
		t.Fatalf("%+v", report)
	}
	if e := lastEntry(t, cb.log, "tls.certificate.import"); e.Outcome != "refused" || e.Code != "TLS_NAMES" {
		t.Fatalf("%+v", e)
	}
}

func TestAnUnservedCertificateIsRolledBack(t *testing.T) {
	cb := newCertBox(t, false, true)
	br := cb.browser()
	br.signIn("alice")
	ctx := context.Background()
	before := served(t, cb.addr)
	l := cb.leaf(t, boxHost)
	imp, err := br.tls().ImportCertificate(ctx, connect.NewRequest(&osadminv1.ImportCertificateRequest{CertificatePem: string(l.PEM), ChainPem: cb.chain(), KeyPem: string(l.KeyPEM)}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = br.tls().AssignCertificate(ctx, connect.NewRequest(&osadminv1.AssignCertificateRequest{EndpointId: "admin", CertificateId: imp.Msg.GetCertificate().GetId()}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "TLS_NOT_SERVED")
	if got := served(t, cb.addr); got != before {
		t.Fatalf("rolled back: %s, want %s", got, before)
	}
	if certstore.AssignedID(cb.adminDir) != "" {
		t.Fatal("no marker after the rollback")
	}
}

func TestACMEAndTheProductEndpointAreNotAvailableYet(t *testing.T) {
	cb := newCertBox(t, false, false)
	br := cb.browser()
	br.signIn("alice")
	ctx := context.Background()
	_, err := br.tls().SetAcme(ctx, connect.NewRequest(&osadminv1.SetAcmeRequest{Issuer: osadminv1.AcmeIssuer_ACME_ISSUER_LETSENCRYPT_STAGING}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "TLS_ACME_UNAVAILABLE")
	_, err = br.tls().RenewNow(ctx, connect.NewRequest(&osadminv1.RenewNowRequest{EndpointId: "admin"}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "TLS_ACME_UNAVAILABLE")
	l := cb.leaf(t, boxHost)
	imp, err := br.tls().ImportCertificate(ctx, connect.NewRequest(&osadminv1.ImportCertificateRequest{CertificatePem: string(l.PEM), ChainPem: cb.chain(), KeyPem: string(l.KeyPEM)}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = br.tls().AssignCertificate(ctx, connect.NewRequest(&osadminv1.AssignCertificateRequest{EndpointId: "product", CertificateId: imp.Msg.GetCertificate().GetId()}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "TLS_ENDPOINT_UNAVAILABLE")
	st, err := br.tls().GetCertificateStore(ctx, connect.NewRequest(&osadminv1.GetCertificateStoreRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	p := st.Msg.GetEndpoints()[1]
	if p.GetId() != "product" || p.GetAvailable() || p.GetUnavailableReason() != "Available when the product is installed." {
		t.Fatalf("%+v", p)
	}
	if !strings.HasPrefix(st.Msg.GetAcme().GetReason(), "Not available yet") {
		t.Fatalf("%+v", st.Msg.GetAcme())
	}
}

func TestStatusWarnsBeforeAnAssignedCertificateExpires(t *testing.T) {
	cb := newCertBox(t, false, false)
	br := cb.browser()
	br.signIn("alice")
	ctx := context.Background()
	l := cb.ca.Issue(t, testpki.LeafOptions{Names: []string{boxHost}, NotBefore: cb.clk.Now().Add(-time.Hour), NotAfter: cb.clk.Now().Add(12 * 24 * time.Hour)})
	imp, err := br.tls().ImportCertificate(ctx, connect.NewRequest(&osadminv1.ImportCertificateRequest{CertificatePem: string(l.PEM), ChainPem: cb.chain(), KeyPem: string(l.KeyPEM)}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := br.tls().AssignCertificate(ctx, connect.NewRequest(&osadminv1.AssignCertificateRequest{EndpointId: "admin", CertificateId: imp.Msg.GetCertificate().GetId()})); err != nil {
		t.Fatal(err)
	}
	st, err := osadminv1connect.NewStatusServiceClient(br.hc, cb.ts.URL).GetStatus(ctx, connect.NewRequest(&osadminv1.GetStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, w := range st.Msg.GetWarnings() {
		if w.GetKind() == osadminv1.WarningKind_WARNING_KIND_SELF_SIGNED_TLS {
			t.Fatal("not self-signed any more")
		}
		if w.GetKind() == osadminv1.WarningKind_WARNING_KIND_TLS_EXPIRING && strings.Contains(w.GetDetail(), "12 days") {
			found = true
		}
	}
	if !found {
		t.Fatalf("%+v", st.Msg.GetWarnings())
	}
}

func TestWithoutAStoreTheCertificatesAreNotAvailable(t *testing.T) {
	b := newBox(t, false)
	br := b.browser()
	br.signIn("alice")
	_, err := br.tls().GetCertificateStore(context.Background(), connect.NewRequest(&osadminv1.GetCertificateStoreRequest{}))
	if err == nil || !strings.Contains(err.Error(), osadmin.NotAvailable) {
		t.Fatalf("%v", err)
	}
}

func TestAWildcardPFXServesThe8443AndAWrongKeyLeavesItInPlace(t *testing.T) {
	cb := newCertBox(t, false, false)
	br := cb.browser()
	br.signIn("alice")
	ctx := context.Background()
	l := cb.leaf(t, "*.sneakers.example.org")
	p12, err := pkcs12.Modern.Encode(l.Key, l.Cert, []*x509.Certificate{cb.ca.Intermediate, cb.ca.Root}, "test-only-password")
	if err != nil {
		t.Fatal(err)
	}
	imp, err := br.tls().ImportCertificate(ctx, connect.NewRequest(&osadminv1.ImportCertificateRequest{Pkcs12: p12, Pkcs12Password: "test-only-password"}))
	if err != nil {
		t.Fatal(err)
	}
	cert := imp.Msg.GetCertificate()
	if _, err := br.tls().AssignCertificate(ctx, connect.NewRequest(&osadminv1.AssignCertificateRequest{EndpointId: "admin", CertificateId: cert.GetId()})); err != nil {
		t.Fatal(err)
	}
	if got := served(t, cb.addr); got != cert.GetFingerprint() {
		t.Fatalf(":8443 serves %s, want the PFX's %s", got, cert.GetFingerprint())
	}

	a, b := cb.leaf(t, boxHost), cb.leaf(t, boxHost)
	_, err = br.tls().ImportCertificate(ctx, connect.NewRequest(&osadminv1.ImportCertificateRequest{CertificatePem: string(a.PEM), ChainPem: cb.chain(), KeyPem: string(b.KeyPEM)}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "TLS_KEY_MISMATCH")
	if got := served(t, cb.addr); got != cert.GetFingerprint() {
		t.Fatal("a refused upload leaves :8443 as it was")
	}
}
