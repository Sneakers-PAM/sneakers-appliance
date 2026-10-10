// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package certstore

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// ProductEdge is the product's edge on 443: the certificate the box hands
// Traefik (the box-tls Secret, internal/productedge).
type ProductEdge interface {
	// Installed reports whether a product is installed, so 443 exists.
	Installed() bool
	// Current is the chain and key the edge has now.
	Current() (crt, key []byte, err error)
	// Set gives the edge crt and key, live.
	Set(crt, key []byte) error
	// Reset puts the box's own certificate (the :8443 one) back, live.
	Reset() error
}

// productEndpoint is the Product (443) endpoint as the page shows it.
func (s *Store) productEndpoint(host string, addrs []string) Endpoint {
	ep := Endpoint{ID: EndpointProduct, Name: "Product (443)", Source: EndpointSelfSigned, Names: boxNames(host, addrs)}
	if s.o.Product == nil || !s.o.Product.Installed() {
		ep.Reason, ep.State, ep.Source = productReason, StateUnavailable, EndpointAssigned
		return ep
	}
	ep.Available = true
	if a, ok := s.st.Endpoints[EndpointProduct]; ok {
		ep.Source, ep.CertificateID = a.Source, a.CertificateID
	}
	crt, _, err := s.o.Product.Current()
	certs, perr := parseCerts("edge", string(crt))
	if err != nil || perr != nil || len(certs) == 0 {
		ep.State, ep.Detail = StateSelfSigned, "443 serves the box's own certificate."
		return ep
	}
	leaf := certs[0]
	ep.Serving, ep.Expires = Fingerprint(leaf.Raw), leaf.NotAfter
	ep.State, ep.Detail = endpointState(leaf, ep.Names, ep.Source == EndpointSelfSigned, s.o.Now(), "443")
	// The product's sign-in, links and OAuth addresses name the box by
	// its host name (package boxvalues), so covering only an address isn't
	// enough here.
	if host != "" && (ep.State == StateOK || ep.State == StateExpiring) && leaf.VerifyHostname(host) != nil {
		ep.State, ep.Detail = StateNames, fmt.Sprintf("The 443 certificate doesn't cover the host name %s, which the product's sign-in, links and OAuth addresses use; it covers %s. Assign one that does (a wildcard for its domain covers it), or change the host name on Network.", host, strings.Join(sanList(leaf), ", "))
	}
	return ep
}

func sanList(leaf *x509.Certificate) []string {
	out := append([]string(nil), leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// endpointState is an endpoint's state for leaf, as adminEndpoint words it.
func endpointState(leaf *x509.Certificate, names []string, self bool, now time.Time, what string) (State, string) {
	left := leaf.NotAfter.Sub(now)
	switch {
	case self:
		return StateSelfSigned, "The box's own self-signed certificate; check its fingerprint."
	case left <= 0:
		return StateExpired, fmt.Sprintf("The %s certificate expired on %s.", what, leaf.NotAfter.UTC().Format(time.DateOnly))
	case len(coveredNames(leaf, names)) == 0:
		return StateNames, fmt.Sprintf("The %s certificate covers none of %s.", what, strings.Join(names, ", "))
	case left <= ExpiryWarning:
		return StateExpiring, fmt.Sprintf("The %s certificate expires in %s (%s); nothing renews it, so upload a new one.", what, days(left), leaf.NotAfter.UTC().Format(time.DateOnly))
	}
	return StateOK, fmt.Sprintf("%s left.", days(left))
}

// assignProduct puts store certificate id in front of the product's edge,
// checks 443 serves it, and puts the previous one back if it doesn't.
func (s *Store) assignProduct(ctx context.Context, id string) (Endpoint, error) {
	i := s.find(id)
	if i < 0 {
		return Endpoint{}, codes.New(codes.TLSUnknown, "no certificate has the id %q", id)
	}
	sc := s.st.Certificates[i]
	c, err := s.view(sc)
	if err != nil {
		return Endpoint{}, err
	}
	host, addrs, err := s.names(ctx)
	if err != nil {
		return Endpoint{}, err
	}
	if s.o.Now().After(c.Leaf.NotAfter) {
		return Endpoint{}, codes.New(codes.TLSValidity, "the certificate expired on %s", c.Leaf.NotAfter.UTC().Format(time.DateOnly))
	}
	if len(coveredNames(c.Leaf, boxNames(host, addrs))) == 0 {
		return Endpoint{}, namesError(c.Leaf, host, addrs)
	}
	key, ok, err := s.o.Sealer.Unseal(sc.KeyItem)
	if err != nil {
		return Endpoint{}, fmt.Errorf("tls: unseal: %w", err)
	}
	if !ok || len(key) == 0 {
		return Endpoint{}, fmt.Errorf("tls: the key of certificate %s isn't sealed on this box", id)
	}
	if err := s.swapProduct(ctx, []byte(sc.PEM), key, c.Fingerprint); err != nil {
		return Endpoint{}, err
	}
	s.st.Endpoints[EndpointProduct] = assignment{Source: EndpointAssigned, CertificateID: id}
	if err := s.save(); err != nil {
		return Endpoint{}, err
	}
	s.o.Logger.Info("tls: certificate assigned", log.F("endpoint", EndpointProduct), log.F("id", id), log.F("fingerprint", c.Fingerprint))
	return s.productEndpoint(host, addrs), nil
}

// revertProduct puts the box's own certificate back in front of the
// product's edge, the one :8443 has (osadmin renews it), checks 443 serves
// it, and puts the assigned one back if it doesn't.
func (s *Store) revertProduct(ctx context.Context) (Endpoint, error) {
	host, addrs, err := s.names(ctx)
	if err != nil {
		return Endpoint{}, err
	}
	prevCrt, prevKey, err := s.o.Product.Current()
	if err != nil {
		return Endpoint{}, fmt.Errorf("tls: the edge's certificate can't be read: %w", err)
	}
	if err := s.o.Product.Reset(); err != nil {
		return Endpoint{}, fmt.Errorf("tls: the edge's certificate can't be written: %w", err)
	}
	crt, _, err := s.o.Product.Current()
	if err != nil {
		return Endpoint{}, fmt.Errorf("tls: the box's own certificate can't be read: %w", err)
	}
	if err := s.probeProduct(ctx, fingerprintPEM(crt), prevCrt, prevKey); err != nil {
		return Endpoint{}, err
	}
	delete(s.st.Endpoints, EndpointProduct)
	if err := s.save(); err != nil {
		return Endpoint{}, err
	}
	s.o.Logger.Info("tls: reverted to self-signed", log.F("endpoint", EndpointProduct), log.F("fingerprint", fingerprintPEM(crt)))
	return s.productEndpoint(host, addrs), nil
}

// swapProduct hands the edge crt and key, waits for 443 to serve fp, and
// puts the previous pair back if it doesn't. It's called holding s.ops
// and s.mu, and lets s.mu go during the check.
func (s *Store) swapProduct(ctx context.Context, crt, key []byte, fp string) error {
	prevCrt, prevKey, err := s.o.Product.Current()
	if err != nil {
		return fmt.Errorf("tls: the edge's certificate can't be read: %w", err)
	}
	if err := s.o.Product.Set(crt, key); err != nil {
		return fmt.Errorf("tls: the edge's certificate can't be written: %w", err)
	}
	return s.probeProduct(ctx, fp, prevCrt, prevKey)
}

// probeProduct waits for 443 to serve fp and gives the edge the previous
// pair back if it doesn't.
func (s *Store) probeProduct(ctx context.Context, fp string, prevCrt, prevKey []byte) error {
	pctx, cancel := context.WithTimeout(ctx, ProductProbeTimeout)
	defer cancel()
	start := time.Now()
	s.mu.Unlock()
	perr := s.o.ProductProbe(pctx, fp)
	s.mu.Lock()
	s.o.Logger.Debug("tls: 443 self-test", log.F("fingerprint", fp), log.F("duration", time.Since(start).String()), log.F("ok", perr == nil))
	if perr != nil {
		if rerr := s.o.Product.Set(prevCrt, prevKey); rerr != nil {
			s.o.Logger.Error(rerr, "tls: the previous product certificate can't be put back")
		}
		s.o.Logger.Warn("tls: 443 didn't serve the new certificate; the previous one is back", log.F("fingerprint", fp), log.F("error", perr.Error()))
		return codes.New(codes.TLSNotServed, "443 didn't serve the new certificate within %s (%v), so the previous one was put back", ProductProbeTimeout, perr)
	}
	return nil
}
