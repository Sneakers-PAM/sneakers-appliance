// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

const mirrorBin = "sneakers-appliance-0.2.0-amd64.bin"

// files is what a test mirror serves, by path.
type files struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (f *files) put(name string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[name] = b
}

func (f *files) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	body, ok := f.m[strings.TrimPrefix(r.URL.Path, "/")]
	f.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(body)
}

// mirrorBox is a box that fetches with its own client, as on the box: the
// roots are roots (standing in for the system's), plus the update trust.
type mirrorBox struct {
	*box
	roots *x509.CertPool
	files *files
}

func newMirrorBox(t *testing.T, direct string) *mirrorBox {
	t.Helper()
	mb := &mirrorBox{roots: x509.NewCertPool(), files: &files{m: map[string][]byte{}}}
	mb.box = newBox(t, true, func(_ *box, o *osadmin.Options) {
		o.Upgrade.HTTPClient = nil
		o.Upgrade.SystemRoots = mb.roots
		o.Upgrade.DirectURL = direct
	})
	return mb
}

// serveHTTPS serves f over TLS on the loopback with a leaf for 127.0.0.1
// from ca, sending the intermediate with it.
func serveHTTPS(t *testing.T, ca *testpki.TLSCA, h http.Handler) (string, testpki.Leaf) {
	t.Helper()
	leaf := ca.Issue(t, testpki.LeafOptions{Names: []string{"127.0.0.1"}})
	cert := tls.Certificate{Certificate: [][]byte{leaf.Cert.Raw, ca.Intermediate.Raw}, PrivateKey: leaf.Key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String(), leaf
}

func (mb *mirrorBox) policy(t *testing.T, br *browser, mirror string, direct bool) {
	t.Helper()
	pol := &osadminv1.UpgradePolicy{Mode: "manual", WindowStart: "02:00", WindowMinutes: 120, MirrorUrl: mirror, Direct: direct}
	if _, err := br.upgrade().SetUpgradePolicy(context.Background(), connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol})); err != nil {
		t.Fatal(err)
	}
}

func fetchBin(br *browser) (*connect.Response[osadminv1.FetchUpdateResponse], error) {
	return br.upgrade().FetchUpdate(context.Background(), connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: mirrorBin}))
}

func mirrorStatus(t *testing.T, br *browser) *osadminv1.MirrorStatus {
	t.Helper()
	g, err := br.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return g.Msg.GetMirrorStatus()
}

func setTrust(br *browser, caPEM []byte, pin string) (*connect.Response[osadminv1.SetUpdateTrustResponse], error) {
	return br.tls().SetUpdateTrust(context.Background(), connect.NewRequest(&osadminv1.SetUpdateTrustRequest{CaPem: string(caPEM), PinSha256: pin}))
}

func sha256Hex(der []byte) string {
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

func TestAPlainHTTPMirrorRestsOnTheSignature(t *testing.T) {
	mb := newMirrorBox(t, "")
	alice := mb.browser()
	alice.signIn("alice")
	srv := httptest.NewServer(mb.files)
	t.Cleanup(srv.Close)
	good := bin(t, mb.sign, mb.enc, full(release.ChannelProduction))
	mb.files.put(mirrorBin, good)
	mb.files.put(updatepkg.IndexName, index(t, productBin(t, mb.sign, mb.enc, "0.2.0", "0.1.0")))
	mb.policy(t, alice, srv.URL, false)

	if st := mirrorStatus(t, alice); st.GetScheme() != "http" || !strings.Contains(st.GetNote(), "plain HTTP: integrity from the signature only") || st.GetChecked() {
		t.Fatalf("before a fetch: %+v", st)
	}
	l, err := alice.upgrade().ListProductVersions(context.Background(), connect.NewRequest(&osadminv1.ListProductVersionsRequest{}))
	if err != nil || len(l.Msg.GetVersions()) != 1 {
		t.Fatalf("%v %v", l, err)
	}
	f, err := fetchBin(alice)
	if err != nil || f.Msg.GetSource() != "mirror" {
		t.Fatalf("%v %v", f, err)
	}
	if st := mirrorStatus(t, alice); !st.GetChecked() || !st.GetOk() || st.GetServerIssuer() != "" {
		t.Fatalf("after a fetch: %+v", st)
	}
	e := lastEntry(t, mb.log, "upgrade.source.fetch")
	if e.Target != srv.URL+"/"+mirrorBin || e.Outcome != "ok" || e.Detail["source"] != "mirror" || e.Detail["ms"] == "" || e.Actor != "alice" {
		t.Fatalf("the fetch's audit entry: %+v", e)
	}
	if err := stage(alice, f.Msg.GetUploadId()); err != nil {
		t.Fatal(err)
	}

	reads := mb.keyReads
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 0xff
	mb.files.put(mirrorBin, tampered)
	f, err = fetchBin(alice)
	if err != nil {
		t.Fatal(err)
	}
	symbolIn(t, stage(alice, f.Msg.GetUploadId()), connect.CodeFailedPrecondition, "UPGRADE_SIGNATURE")
	if mb.keyReads != reads {
		t.Fatal("a tampered .bin from a plain HTTP mirror was decrypted")
	}
}

func TestAnHTTPSMirrorWithAPublicCertificate(t *testing.T) {
	mb := newMirrorBox(t, "")
	public := testpki.NewTLSCA(t)
	mb.roots.AddCert(public.Root)
	url, leaf := serveHTTPS(t, public, mb.files)
	mb.files.put(mirrorBin, bin(t, mb.sign, mb.enc, full(release.ChannelProduction)))
	alice := mb.browser()
	alice.signIn("alice")
	mb.policy(t, alice, url, false)
	if _, err := fetchBin(alice); err != nil {
		t.Fatal(err)
	}
	st := mirrorStatus(t, alice)
	if st.GetScheme() != "https" || !st.GetOk() || st.GetCustomCa() || st.GetPinned() || st.GetServerIssuer() != public.Intermediate.Subject.CommonName ||
		st.GetServerSubject() != "127.0.0.1" || !st.GetServerNotAfter().AsTime().Equal(leaf.Cert.NotAfter) || st.GetServerSha256() != osadmin.Fingerprint(leaf.Cert.Raw) {
		t.Fatalf("%+v", st)
	}
}

func TestAnHTTPSMirrorWithAPrivateCA(t *testing.T) {
	private := testpki.NewTLSCA(t)
	directFiles := &files{m: map[string][]byte{}}
	directURL, _ := serveHTTPS(t, private, directFiles)
	mb := newMirrorBox(t, directURL+"/direct")
	url, leaf := serveHTTPS(t, private, mb.files)
	good := bin(t, mb.sign, mb.enc, full(release.ChannelProduction))
	mb.files.put(mirrorBin, good)
	alice, bob := mb.browser(), mb.browser()
	alice.signIn("alice")
	bob.signIn("bob")
	mb.policy(t, alice, url, false)

	_, err := fetchBin(alice)
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_MIRROR_UNTRUSTED")
	if !strings.Contains(err.Error(), osadmin.Fingerprint(leaf.Cert.Raw)) {
		t.Fatalf("the refusal names the presented certificate: %v", err)
	}
	st := mirrorStatus(t, alice)
	if st.GetOk() || st.GetCode() != "UPGRADE_MIRROR_UNTRUSTED" || st.GetServerIssuer() != private.Intermediate.Subject.CommonName {
		t.Fatalf("%+v", st)
	}
	if e := lastEntry(t, mb.log, "upgrade.source.fetch"); e.Outcome != "refused" || e.Code != "UPGRADE_MIRROR_UNTRUSTED" {
		t.Fatalf("%+v", e)
	}

	_, err = setTrust(bob, private.RootPEM, "")
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	// An owner sets it with no authenticator code.
	tr, err := setTrust(alice, private.RootPEM, "")
	if err != nil {
		t.Fatal(err)
	}
	if cas := tr.Msg.GetUpdateTrust().GetCas(); len(cas) != 1 || cas[0].GetSubject() != private.Root.Subject.CommonName || cas[0].GetSha256() != osadmin.Fingerprint(private.Root.Raw) {
		t.Fatalf("%+v", tr.Msg)
	}
	if e := lastEntry(t, mb.log, "tls.update-trust.set"); e.Outcome != "ok" || e.Actor != "alice" {
		t.Fatalf("%+v", e)
	}
	f, err := fetchBin(alice)
	if err != nil {
		t.Fatal(err)
	}
	if st := mirrorStatus(t, alice); !st.GetOk() || !st.GetCustomCa() {
		t.Fatalf("%+v", st)
	}
	// One file at a time: the fetched file goes before the next fetch.
	if _, err := alice.discard(f.Msg.GetUploadId(), 0); err != nil {
		t.Fatal(err)
	}

	// The private CA is the mirror's only: the release source isn't
	// trusted through it.
	directFiles.put("direct/latest/download/"+mirrorBin, good)
	mb.policy(t, alice, "", true)
	_, err = fetchBin(alice)
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_UPLOAD")

	mb.policy(t, alice, url, false)
	if _, err := alice.tls().ClearUpdateTrust(context.Background(), connect.NewRequest(&osadminv1.ClearUpdateTrustRequest{})); err != nil {
		t.Fatal(err)
	}
	_, err = fetchBin(alice)
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_MIRROR_UNTRUSTED")
	if st := mirrorStatus(t, alice); st.GetCustomCa() {
		t.Fatalf("cleared: %+v", st)
	}
}

func TestAMirrorUnderAnotherCAIsRefused(t *testing.T) {
	mb := newMirrorBox(t, "")
	url, _ := serveHTTPS(t, testpki.NewTLSCA(t), mb.files)
	mb.files.put(mirrorBin, bin(t, mb.sign, mb.enc, full(release.ChannelProduction)))
	alice := mb.browser()
	alice.signIn("alice")
	mb.policy(t, alice, url, false)
	if _, err := setTrust(alice, testpki.NewTLSCA(t).RootPEM, ""); err != nil {
		t.Fatal(err)
	}
	_, err := fetchBin(alice)
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_MIRROR_UNTRUSTED")
	if mb.unpacked(t) {
		t.Fatal("unpacked")
	}
}

func TestAPinThatDoesntMatchIsRefused(t *testing.T) {
	mb := newMirrorBox(t, "")
	ca := testpki.NewTLSCA(t)
	url, leaf := serveHTTPS(t, ca, mb.files)
	mb.files.put(mirrorBin, bin(t, mb.sign, mb.enc, full(release.ChannelProduction)))
	alice := mb.browser()
	alice.signIn("alice")
	mb.policy(t, alice, url, false)

	other := ca.Issue(t, testpki.LeafOptions{Names: []string{"127.0.0.1"}})
	if _, err := setTrust(alice, ca.RootPEM, osadmin.Fingerprint(other.Cert.Raw)); err != nil {
		t.Fatal(err)
	}
	_, err := fetchBin(alice)
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_MIRROR_PIN")
	st := mirrorStatus(t, alice)
	if st.GetOk() || !st.GetPinned() || st.GetPinMatched() || st.GetCode() != "UPGRADE_MIRROR_PIN" || st.GetServerSha256() != osadmin.Fingerprint(leaf.Cert.Raw) {
		t.Fatalf("%+v", st)
	}

	// openssl's form: lower case, no colons.
	tr, err := setTrust(alice, ca.RootPEM, sha256Hex(leaf.Cert.Raw))
	if err != nil {
		t.Fatal(err)
	}
	if tr.Msg.GetUpdateTrust().GetPinSha256() != osadmin.Fingerprint(leaf.Cert.Raw) {
		t.Fatalf("the pin is kept in colon form: %q", tr.Msg.GetUpdateTrust().GetPinSha256())
	}
	if _, err := fetchBin(alice); err != nil {
		t.Fatal(err)
	}
	if st := mirrorStatus(t, alice); !st.GetOk() || !st.GetPinMatched() {
		t.Fatalf("%+v", st)
	}
}

func TestThePinNeverReplacesTheChain(t *testing.T) {
	mb := newMirrorBox(t, "")
	url, leaf := serveHTTPS(t, testpki.NewTLSCA(t), mb.files)
	mb.files.put(mirrorBin, bin(t, mb.sign, mb.enc, full(release.ChannelProduction)))
	alice := mb.browser()
	alice.signIn("alice")
	mb.policy(t, alice, url, false)
	if _, err := setTrust(alice, nil, osadmin.Fingerprint(leaf.Cert.Raw)); err != nil {
		t.Fatal(err)
	}
	_, err := fetchBin(alice)
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_MIRROR_UNTRUSTED")
}

func TestTheUpdateTrustIsChecked(t *testing.T) {
	mb := newMirrorBox(t, "")
	alice := mb.browser()
	alice.signIn("alice")
	ca := testpki.NewTLSCA(t)
	leaf := ca.Issue(t, testpki.LeafOptions{Names: []string{"mirror.example.org"}})
	expired := ca.Issue(t, testpki.LeafOptions{IsCA: true, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)})
	for _, tc := range []struct {
		name, symbol string
		pemCA        []byte
		pin          string
	}{
		{"nothing", "TLS_INVALID", nil, ""},
		{"not PEM", "TLS_FORMAT", []byte("hello"), ""},
		{"a server certificate", "TLS_USAGE", leaf.PEM, ""},
		{"an expired CA", "TLS_VALIDITY", expired.PEM, ""},
		{"a short pin", "TLS_INVALID", ca.RootPEM, "AB:CD"},
		{"a pin that isn't hex", "TLS_INVALID", ca.RootPEM, strings.Repeat("zz", 32)},
	} {
		_, err := setTrust(alice, tc.pemCA, tc.pin)
		if err == nil || !strings.Contains(err.Error(), tc.symbol) {
			t.Errorf("%s: want %s, got %v", tc.name, tc.symbol, err)
		}
	}
	if st := mirrorStatus(t, alice); st != nil {
		t.Fatalf("no mirror, no status: %+v", st)
	}
}

func TestTheMirrorIsAnHTTPOrHTTPSURLWithoutCredentials(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	for _, u := range []string{"http://192.0.2.20/updates", "https://mirror.example.org/sneakers/"} {
		pol := &osadminv1.UpgradePolicy{Mode: "manual", WindowStart: "02:00", WindowMinutes: 120, MirrorUrl: u}
		if _, err := alice.upgrade().SetUpgradePolicy(context.Background(), connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol})); err != nil {
			t.Fatalf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"ftp://mirror.example.org", "https://user:pass@mirror.example.org", "http://mirror.example.org/?token=x", "http:///updates", "mirror.example.org"} {
		pol := &osadminv1.UpgradePolicy{Mode: "manual", WindowStart: "02:00", WindowMinutes: 120, MirrorUrl: u}
		_, err := alice.upgrade().SetUpgradePolicy(context.Background(), connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol}))
		symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_CONFIRM")
	}
}

func TestARedirectThatDropsTLSIsRefused(t *testing.T) {
	mb := newMirrorBox(t, "")
	plain := httptest.NewServer(mb.files)
	t.Cleanup(plain.Close)
	public := testpki.NewTLSCA(t)
	mb.roots.AddCert(public.Root)
	url, _ := serveHTTPS(t, public, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusFound)
	}))
	mb.files.put(mirrorBin, bin(t, mb.sign, mb.enc, full(release.ChannelProduction)))
	alice := mb.browser()
	alice.signIn("alice")
	mb.policy(t, alice, url, false)
	_, err := fetchBin(alice)
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_UPLOAD")
}
