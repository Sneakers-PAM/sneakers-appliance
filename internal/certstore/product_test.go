// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package certstore_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
)

// fakeEdge is the product's edge (443): what it serves, and whether a
// product is installed.
type fakeEdge struct {
	mu        sync.Mutex
	installed bool
	crt, key  []byte
	sets      int
	// own is the box's own certificate, what Reset puts back.
	own []byte
}

func (e *fakeEdge) Installed() bool { e.mu.Lock(); defer e.mu.Unlock(); return e.installed }

func (e *fakeEdge) Current() ([]byte, []byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.crt, e.key, nil
}

func (e *fakeEdge) Set(crt, key []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.crt, e.key = crt, key
	e.sets++
	return nil
}

// Reset is the box's own certificate back: the fixture's :8443 files.
func (e *fakeEdge) Reset() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.crt, e.key = e.own, []byte("own-key")
	e.sets++
	return nil
}

func productFixture(t *testing.T, e *fakeEdge, probe func(context.Context, string) error) *fixture {
	t.Helper()
	f := newFixture(t)
	f.s.SetProduct(e, probe)
	return f
}

// Once a product is installed the Product (443) endpoint takes a store
// certificate: it goes in front of the edge, 443 is checked to serve it,
// and Revert puts the box's own self-signed one back.
func TestTheProductEndpointTakesACertificateAndReverts(t *testing.T) {
	e := &fakeEdge{}
	var probed []string
	f := productFixture(t, e, func(_ context.Context, fp string) error { probed = append(probed, fp); return nil })
	e.own = f.read("tls.crt")
	ctx := context.Background()
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}})
	c, _, err := f.s.Import(ctx, certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: f.chain(), KeyPEM: string(l.KeyPEM)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.s.Assign(ctx, certstore.EndpointProduct, c.ID)
	wantCode(t, err, codes.TLSEndpointUnavailable, "")
	snap, _ := f.s.Snapshot(ctx)
	if ep := endpoint(snap, certstore.EndpointProduct); ep.Available {
		t.Fatalf("available with no product: %+v", ep)
	}

	e.installed = true
	ep, err := f.s.Assign(ctx, certstore.EndpointProduct, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ep.ID != certstore.EndpointProduct || !ep.Available || ep.Source != certstore.EndpointAssigned || ep.CertificateID != c.ID || ep.Serving != c.Fingerprint {
		t.Fatalf("%+v", ep)
	}
	if string(e.crt) == "" || len(probed) != 1 || probed[0] != c.Fingerprint {
		t.Fatalf("edge %d bytes, probed %v", len(e.crt), probed)
	}
	if err := f.s.Delete(c.ID); !codes.Is(err, codes.TLSInUse) {
		t.Fatalf("deleting a certificate the product uses: %v", err)
	}
	// The admin endpoint is untouched.
	snap, _ = f.s.Snapshot(ctx)
	if a := endpoint(snap, certstore.EndpointAdmin); a.Source != certstore.EndpointSelfSigned {
		t.Fatalf("admin %+v", a)
	}

	ep, err = f.s.Revert(ctx, certstore.EndpointProduct)
	if err != nil || ep.Source != certstore.EndpointSelfSigned || ep.Serving == c.Fingerprint || string(e.crt) != string(e.own) {
		t.Fatalf("%+v %v", ep, err)
	}
	if len(probed) != 2 || probed[1] != ep.Serving {
		t.Fatalf("probed %v", probed)
	}
	if err := f.s.Delete(c.ID); err != nil {
		t.Fatalf("deleting it once reverted: %v", err)
	}
}

// When 443 doesn't serve the new certificate in time, the previous one is
// put back and the assignment fails, saying so.
func TestAProductCertificateThatIsntServedIsRolledBack(t *testing.T) {
	e := &fakeEdge{installed: true, crt: []byte("previous"), key: []byte("previous-key")}
	f := productFixture(t, e, func(context.Context, string) error { return errors.New("443 still serves the old one") })
	ctx := context.Background()
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}})
	c, _, err := f.s.Import(ctx, certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: f.chain(), KeyPEM: string(l.KeyPEM)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.s.Assign(ctx, certstore.EndpointProduct, c.ID)
	wantCode(t, err, codes.TLSNotServed, "")
	if string(e.crt) != "previous" || string(e.key) != "previous-key" || e.sets != 2 {
		t.Fatalf("not rolled back: %q after %d sets", e.crt, e.sets)
	}
	snap, _ := f.s.Snapshot(ctx)
	if ep := endpoint(snap, certstore.EndpointProduct); ep.CertificateID == c.ID {
		t.Fatalf("recorded as assigned: %+v", ep)
	}
}

// The product's certificate must cover the box's names, like :8443's.
func TestAProductCertificateMustCoverTheBox(t *testing.T) {
	e := &fakeEdge{installed: true}
	f := productFixture(t, e, func(context.Context, string) error { return nil })
	ctx := context.Background()
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{"other.example.org", host}})
	c, _, err := f.s.Import(ctx, certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: f.chain(), KeyPEM: string(l.KeyPEM)})
	if err != nil {
		t.Fatal(err)
	}
	f.host = "elsewhere.example.org"
	f.addrs = []string{"192.0.2.99"}
	_, err = f.s.Assign(ctx, certstore.EndpointProduct, c.ID)
	if !codes.Is(err, codes.TLSNames) && !codes.Is(err, codes.TLSNoHostname) {
		t.Fatalf("err %v", err)
	}
	if e.sets != 0 {
		t.Fatal("the edge was changed")
	}
}

func endpoint(s certstore.Snapshot, id string) certstore.Endpoint {
	for _, e := range s.Endpoints {
		if e.ID == id {
			return e
		}
	}
	return certstore.Endpoint{}
}
