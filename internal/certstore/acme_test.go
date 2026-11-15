// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package certstore_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/acme"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
)

// fakeACME is cert-manager on the box: it keeps what the box applied, and
// answers with whatever the test says cert-manager has made.
type fakeACME struct {
	mu        sync.Mutex
	available bool
	reason    string
	applied   [][]byte
	removed   int
	status    certstore.ACMEStatus
	statusErr error
	applyErr  error
}

func (a *fakeACME) Available() (bool, string) { return a.available, a.reason }

func (a *fakeACME) Apply(_ context.Context, manifests []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.applyErr != nil {
		return a.applyErr
	}
	a.applied = append(a.applied, manifests)
	return nil
}

func (a *fakeACME) Remove(context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.removed++
	return nil
}

func (a *fakeACME) Status(context.Context) (certstore.ACMEStatus, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.status, a.statusErr
}

func (a *fakeACME) last(t *testing.T) string {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.applied) == 0 {
		t.Fatal("nothing was applied")
	}
	return string(a.applied[len(a.applied)-1])
}

// issued makes the pair cert-manager would put in its Secret.
func issued(t *testing.T, f *fixture, notAfter time.Time) certstore.ACMEStatus {
	t.Helper()
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}, NotAfter: notAfter})
	return certstore.ACMEStatus{Ready: true, CertPEM: l.PEM, KeyPEM: l.KeyPEM}
}

func acmeFixture(t *testing.T) (*fixture, *fakeACME, *fakeEdge) {
	t.Helper()
	e := &fakeEdge{installed: true}
	f := productFixture(t, e, func(_ context.Context, fp string) error { f0 := fp; _ = f0; return nil })
	e.own = f.read("tls.crt")
	d := &fakeACME{available: true}
	f.s.SetACMEDriver(d)
	return f, d, e
}

var stagingHTTP = certstore.ACMERequest{
	Config:      acme.Config{Issuer: acme.IssuerStaging, Email: "ops@example.org", Challenge: acme.ChallengeHTTP01},
	EndpointIDs: []string{certstore.EndpointProduct},
}

func TestACMEIsUnavailableWhereCertManagerCantRun(t *testing.T) {
	f, d, _ := acmeFixture(t)
	d.available, d.reason = false, "cert-manager isn't running yet"
	ctx := context.Background()
	snap, err := f.s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.ACME.Available || snap.ACME.Reason != "cert-manager isn't running yet" {
		t.Fatalf("%+v", snap.ACME)
	}
	err = f.s.ConfigureACME(ctx, stagingHTTP)
	wantCode(t, err, codes.TLSACMEUnavailable, "cert-manager isn't running yet")
	if len(d.applied) != 0 {
		t.Fatal("nothing may be applied where ACME can't run")
	}
	// No driver at all (a box with no product bundle) is the same answer.
	f.s.SetACMEDriver(nil)
	wantCode(t, f.s.ConfigureACME(ctx, stagingHTTP), codes.TLSACMEUnavailable, "")
}

func TestSettingACMEAppliesTheStackAndWaitsForTheCertificate(t *testing.T) {
	f, d, e := acmeFixture(t)
	ctx := context.Background()
	if err := f.s.ConfigureACME(ctx, stagingHTTP); err != nil {
		t.Fatal(err)
	}
	if got := d.last(t); !strings.Contains(got, "kind: Issuer") || !strings.Contains(got, host) {
		t.Fatalf("stack:\n%s", got)
	}
	snap, _ := f.s.Snapshot(ctx)
	ep := endpoint(snap, certstore.EndpointProduct)
	if ep.Source != certstore.EndpointACME || !strings.Contains(ep.Detail, "waiting") {
		t.Fatalf("endpoint %+v", ep)
	}
	if e.sets != 0 {
		t.Fatal("443 keeps the box's own certificate until the CA has issued")
	}
	// Nothing issued yet: a look finds nothing to do.
	ev, err := f.s.SyncACME(ctx)
	if err != nil || len(ev) != 0 {
		t.Fatalf("events %+v, err %v", ev, err)
	}
}

func TestAnIssuedCertificateGoesThroughTheAssignPath(t *testing.T) {
	f, d, e := acmeFixture(t)
	var probed []string
	f.s.SetProduct(e, func(_ context.Context, fp string) error { probed = append(probed, fp); return nil })
	ctx := context.Background()
	if err := f.s.ConfigureACME(ctx, stagingHTTP); err != nil {
		t.Fatal(err)
	}
	d.status = issued(t, f, time.Now().Add(80*24*time.Hour))
	ev, err := f.s.SyncACME(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0].Kind != certstore.ACMEIssued || ev[0].Endpoint != certstore.EndpointProduct {
		t.Fatalf("events %+v", ev)
	}
	snap, _ := f.s.Snapshot(ctx)
	ep := endpoint(snap, certstore.EndpointProduct)
	if ep.Source != certstore.EndpointACME || ep.State != certstore.StateOK || ep.Serving == "" {
		t.Fatalf("endpoint %+v", ep)
	}
	if len(probed) != 1 || probed[0] != ep.Serving {
		t.Fatalf("443 was checked for %v, serving %s", probed, ep.Serving)
	}
	var found bool
	for _, c := range snap.Certificates {
		if c.Source == certstore.SourceACME && c.ID == ep.CertificateID {
			found = true
		}
	}
	if !found {
		t.Fatalf("the store has no ACME certificate: %+v", snap.Certificates)
	}
	// A second look at the same pair does nothing.
	if ev, _ := f.s.SyncACME(ctx); len(ev) != 0 {
		t.Fatalf("again: %+v", ev)
	}
}

func TestRenewalReplacesTheCertificateAndDropsTheOldOne(t *testing.T) {
	f, d, _ := acmeFixture(t)
	ctx := context.Background()
	_ = f.s.ConfigureACME(ctx, stagingHTTP)
	d.status = issued(t, f, time.Now().Add(20*24*time.Hour))
	if _, err := f.s.SyncACME(ctx); err != nil {
		t.Fatal(err)
	}
	snap, _ := f.s.Snapshot(ctx)
	first := endpoint(snap, certstore.EndpointProduct).CertificateID
	d.status = issued(t, f, time.Now().Add(90*24*time.Hour))
	ev, err := f.s.SyncACME(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0].Kind != certstore.ACMERenewed {
		t.Fatalf("events %+v", ev)
	}
	snap, _ = f.s.Snapshot(ctx)
	second := endpoint(snap, certstore.EndpointProduct).CertificateID
	if second == first {
		t.Fatal("the endpoint still has the old certificate")
	}
	for _, c := range snap.Certificates {
		if c.ID == first {
			t.Fatal("the old ACME certificate is still in the store")
		}
	}
}

func TestAFailedRenewalShowsAndIsReportedOnce(t *testing.T) {
	f, d, _ := acmeFixture(t)
	ctx := context.Background()
	_ = f.s.ConfigureACME(ctx, stagingHTTP)
	d.status = issued(t, f, time.Now().Add(10*24*time.Hour))
	if _, err := f.s.SyncACME(ctx); err != nil {
		t.Fatal(err)
	}
	d.status.Failure = "the CA refused the challenge: 403 from the solver"
	ev, _ := f.s.SyncACME(ctx)
	if len(ev) != 1 || ev[0].Kind != certstore.ACMEFailed || !strings.Contains(ev[0].Message, "403") {
		t.Fatalf("events %+v", ev)
	}
	snap, _ := f.s.Snapshot(ctx)
	ep := endpoint(snap, certstore.EndpointProduct)
	if !strings.Contains(ep.Detail, "403 from the solver") {
		t.Fatalf("the page doesn't say why: %q", ep.Detail)
	}
	if ev, _ := f.s.SyncACME(ctx); len(ev) != 0 {
		t.Fatalf("the same failure must not be reported every minute: %+v", ev)
	}
	// Once cert-manager recovers, the failure clears.
	d.status = issued(t, f, time.Now().Add(90*24*time.Hour))
	if ev, _ := f.s.SyncACME(ctx); len(ev) != 1 || ev[0].Kind != certstore.ACMERenewed {
		t.Fatalf("after recovery: %+v", ev)
	}
	snap, _ = f.s.Snapshot(ctx)
	if d := endpoint(snap, certstore.EndpointProduct).Detail; strings.Contains(d, "403") {
		t.Fatalf("the failure stayed on the page: %q", d)
	}
}

func TestACertificateThatIsntServedIsRolledBackAndTriedAgain(t *testing.T) {
	f, d, e := acmeFixture(t)
	fail := true
	f.s.SetProduct(e, func(_ context.Context, fp string) error {
		if fail {
			return errors.New("443 still serves the old one")
		}
		return nil
	})
	ctx := context.Background()
	_ = f.s.ConfigureACME(ctx, stagingHTTP)
	d.status = issued(t, f, time.Now().Add(80*24*time.Hour))
	ev, _ := f.s.SyncACME(ctx)
	if len(ev) != 1 || ev[0].Kind != certstore.ACMEFailed {
		t.Fatalf("events %+v", ev)
	}
	snap, _ := f.s.Snapshot(ctx)
	if ep := endpoint(snap, certstore.EndpointProduct); ep.CertificateID != "" && ep.State == certstore.StateOK {
		t.Fatalf("a certificate that wasn't served is assigned: %+v", ep)
	}
	fail = false
	ev, _ = f.s.SyncACME(ctx)
	if len(ev) != 1 || ev[0].Kind != certstore.ACMEIssued {
		t.Fatalf("the next look should apply it: %+v", ev)
	}
}

func TestRevertingTheLastACMEEndpointRemovesTheStack(t *testing.T) {
	f, d, _ := acmeFixture(t)
	ctx := context.Background()
	_ = f.s.ConfigureACME(ctx, stagingHTTP)
	d.status = issued(t, f, time.Now().Add(80*24*time.Hour))
	if _, err := f.s.SyncACME(ctx); err != nil {
		t.Fatal(err)
	}
	ep, err := f.s.Revert(ctx, certstore.EndpointProduct)
	if err != nil {
		t.Fatal(err)
	}
	if ep.Source != certstore.EndpointSelfSigned {
		t.Fatalf("%+v", ep)
	}
	if d.removed != 1 {
		t.Fatalf("the stack was removed %d times", d.removed)
	}
	snap, _ := f.s.Snapshot(ctx)
	for _, c := range snap.Certificates {
		if c.Source == certstore.SourceACME {
			t.Fatalf("an ACME certificate outlived its endpoint: %+v", c)
		}
	}
	// Nothing left to follow.
	if ev, _ := f.s.SyncACME(ctx); len(ev) != 0 {
		t.Fatalf("%+v", ev)
	}
}

func TestRenewNowChangesWhatIsAppliedAndNeedsACMEFirst(t *testing.T) {
	f, d, _ := acmeFixture(t)
	ctx := context.Background()
	wantCode(t, f.s.RenewACME(ctx, certstore.EndpointProduct), codes.TLSInvalid, "isn't using ACME")
	_ = f.s.ConfigureACME(ctx, stagingHTTP)
	before := len(d.applied)
	if err := f.s.RenewACME(ctx, certstore.EndpointProduct); err != nil {
		t.Fatal(err)
	}
	if len(d.applied) != before+1 || !strings.Contains(d.last(t), "renewal-1") {
		t.Fatalf("applied %d times, last:\n%s", len(d.applied), d.last(t))
	}
}

func TestTheDNSTokenIsSealedAndKeptWhenLeftEmpty(t *testing.T) {
	f, d, _ := acmeFixture(t)
	ctx := context.Background()
	req := certstore.ACMERequest{
		Config:      acme.Config{Issuer: acme.IssuerProduction, Email: "ops@example.org", Challenge: acme.ChallengeDNS01, DNSProvider: acme.ProviderCloudflare, DNSToken: "tok-1"},
		EndpointIDs: []string{certstore.EndpointProduct},
	}
	if err := f.s.ConfigureACME(ctx, req); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(f.dir, "store.json")); err != nil || strings.Contains(string(b), "tok-1") {
		t.Fatalf("the store's file must not hold the token (err %v)", err)
	}
	var sealed bool
	for _, v := range f.sealer.items {
		if strings.Contains(string(v), "tok-1") {
			sealed = true
		}
	}
	if !sealed {
		t.Fatal("the token isn't sealed on the box")
	}
	// A change with no token keeps the one sealed.
	req.Config.DNSToken = ""
	req.Config.Email = "other@example.org"
	if err := f.s.ConfigureACME(ctx, req); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.last(t), "tok-1") {
		t.Fatal("the kept token isn't in the new stack")
	}
	// No token, none kept: refused.
	f2, _, _ := acmeFixture(t)
	req.Config.DNSToken = ""
	wantCode(t, f2.s.ConfigureACME(ctx, req), codes.TLSInvalid, "API token")
	// A snapshot never carries the token.
	snap, _ := f.s.Snapshot(ctx)
	if strings.Contains(strings.Join([]string{snap.ACME.Reason}, ""), "tok-1") {
		t.Fatal("the token leaked into the snapshot")
	}
}
