// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package certstore

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/acme"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// ACMEUnavailableReason is why ACME isn't offered when no driver is wired:
// the box has no product bundle, so no cert-manager runs.
const ACMEUnavailableReason = "ACME needs the product bundle's cert-manager, which runs once a product is installed."

// The sealed items an ACME setup keeps: the DNS provider's token and the
// External Account Binding key. Neither is returned or written to the
// store's file.
const (
	acmeTokenItem = "tls-acme-dns"
	acmeEABItem   = "tls-acme-eab"
)

// ACMEDriver is cert-manager on the box: the stack it's given to issue
// from, and what it has made.
type ACMEDriver interface {
	// Available says whether cert-manager can run here, and why not.
	Available() (ok bool, reason string)
	// Apply makes manifests the box's ACME stack, replacing the one before.
	Apply(ctx context.Context, manifests []byte) error
	// Remove takes the stack away; cert-manager then forgets the Issuer
	// and the Certificate.
	Remove(ctx context.Context) error
	// Status is what cert-manager has made so far.
	Status(ctx context.Context) (ACMEStatus, error)
}

// ACMEStatus is cert-manager's answer: the issued pair when there is one
// (kept across a failing renewal) and the latest failure when there is one.
type ACMEStatus struct {
	// Ready is the Certificate's Ready condition.
	Ready bool
	// Failure is why issuing or renewing fails now; empty when it doesn't.
	Failure         string
	CertPEM, KeyPEM []byte
}

// ACMERequest is what an owner chooses: the CA, the challenge and the
// endpoints that take the certificate. The tokens are write-only: an empty
// one keeps the one already sealed.
type ACMERequest struct {
	Config      acme.Config
	EndpointIDs []string
}

// ACMEEventKind says what the follower did.
type ACMEEventKind string

// The events SyncACME reports, each for the audit log.
const (
	// ACMEIssued is the first certificate an endpoint takes from the CA.
	ACMEIssued ACMEEventKind = "issued"
	// ACMERenewed is a certificate that replaced an earlier one.
	ACMERenewed ACMEEventKind = "renewed"
	// ACMEFailed is issuing, renewing or applying that doesn't work; it's
	// reported when the reason first appears or changes.
	ACMEFailed ACMEEventKind = "failed"
)

// ACMEEvent is one thing the follower did or found.
type ACMEEvent struct {
	Kind ACMEEventKind
	// Endpoint is the endpoint concerned; empty for a failure that's the
	// CA's, not an endpoint's.
	Endpoint    string
	Fingerprint string
	Expires     time.Time
	Names       []string
	Message     string
}

// acmeState is what the store keeps about ACME. It holds no secret.
type acmeState struct {
	Issuer       string   `json:"issuer"`
	DirectoryURL string   `json:"directoryUrl,omitempty"`
	Email        string   `json:"email"`
	Challenge    string   `json:"challenge"`
	DNSProvider  string   `json:"dnsProvider,omitempty"`
	EABKeyID     string   `json:"eabKeyId,omitempty"`
	Endpoints    []string `json:"endpoints"`
	// Renewal counts the renew-now requests; it goes into the stack so
	// cert-manager issues again.
	Renewal int `json:"renewal,omitempty"`
	// Applied is the fingerprint of the certificate last taken from
	// cert-manager by every endpoint.
	Applied string `json:"applied,omitempty"`
	// Failure is the last problem reported, until it clears.
	Failure string `json:"failure,omitempty"`
}

func (s *Store) acmeOK() (bool, string) {
	if s.o.ACME == nil {
		return false, ACMEUnavailableReason
	}
	return s.o.ACME.Available()
}

// acmeNames are the names the box asks the CA for: its host name.
func (s *Store) acmeNames(ctx context.Context) ([]string, error) {
	host, _, err := s.names(ctx)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return nil, nil
	}
	return []string{host}, nil
}

// acmeConfig is the Config a state and its sealed secrets make.
func (s *Store) acmeConfig(a *acmeState) (acme.Config, error) {
	c := acme.Config{Issuer: a.Issuer, DirectoryURL: a.DirectoryURL, Email: a.Email, Challenge: a.Challenge, DNSProvider: a.DNSProvider, EABKeyID: a.EABKeyID}
	if a.Challenge == acme.ChallengeDNS01 {
		tok, _, err := s.o.Sealer.Unseal(acmeTokenItem)
		if err != nil {
			return c, fmt.Errorf("tls: unseal: %w", err)
		}
		c.DNSToken = string(tok)
	}
	if a.EABKeyID != "" {
		k, _, err := s.o.Sealer.Unseal(acmeEABItem)
		if err != nil {
			return c, fmt.Errorf("tls: unseal: %w", err)
		}
		c.EABHMACKey = string(k)
	}
	return c, nil
}

// ConfigureACME makes the chosen endpoints take their certificate from
// cert-manager: it writes the stack and returns, and SyncACME takes the
// certificate once the CA has issued it. Until then each endpoint keeps
// what it serves.
func (s *Store) ConfigureACME(ctx context.Context, r ACMERequest) error {
	defer s.change()()
	lg := s.o.Logger
	if ok, reason := s.acmeOK(); !ok {
		lg.Info("tls: acme refused: cert-manager can't run here", log.F("reason", reason))
		return codes.New(codes.TLSACMEUnavailable, "%s", reason)
	}
	if len(r.EndpointIDs) == 0 {
		return codes.New(codes.TLSInvalid, "acme: name the endpoints that take the certificate")
	}
	for _, ep := range r.EndpointIDs {
		if err := s.checkEndpoint(ep); err != nil {
			return err
		}
	}
	names, err := s.acmeNames(ctx)
	if err != nil {
		return err
	}
	cfg := r.Config
	if cfg.Challenge == acme.ChallengeDNS01 && cfg.DNSToken == "" {
		tok, _, err := s.o.Sealer.Unseal(acmeTokenItem)
		if err != nil {
			return fmt.Errorf("tls: unseal: %w", err)
		}
		cfg.DNSToken = string(tok)
	}
	if cfg.EABKeyID != "" && cfg.EABHMACKey == "" {
		k, _, err := s.o.Sealer.Unseal(acmeEABItem)
		if err != nil {
			return fmt.Errorf("tls: unseal: %w", err)
		}
		cfg.EABHMACKey = string(k)
	}
	renewal := 0
	if s.st.ACME != nil {
		renewal = s.st.ACME.Renewal
	}
	manifests, err := acme.Render(cfg, names, renewal)
	if err != nil {
		lg.Info("tls: acme refused", log.F("reason", sentence(err)))
		return err
	}
	for item, v := range map[string]string{acmeTokenItem: cfg.DNSToken, acmeEABItem: cfg.EABHMACKey} {
		if err := s.o.Sealer.Seal(item, []byte(v)); err != nil {
			return fmt.Errorf("tls: seal: %w", err)
		}
	}
	start := time.Now()
	if err := s.o.ACME.Apply(ctx, manifests); err != nil {
		lg.Error(err, "tls: the ACME stack can't be written", log.F("duration", time.Since(start).String()))
		return fmt.Errorf("tls: the ACME stack can't be written: %w", err)
	}
	lg.Info("tls: acme configured", log.F("issuer", cfg.Issuer), log.F("challenge", cfg.Challenge), log.F("endpoints", strings.Join(r.EndpointIDs, ",")), log.F("names", strings.Join(names, ",")), log.F("duration", time.Since(start).String()))
	prev := s.st.ACME
	s.st.ACME = &acmeState{Issuer: cfg.Issuer, DirectoryURL: cfg.DirectoryURL, Email: cfg.Email, Challenge: cfg.Challenge, DNSProvider: cfg.DNSProvider,
		EABKeyID: cfg.EABKeyID, Endpoints: slices.Clone(r.EndpointIDs), Renewal: renewal}
	if prev != nil && slices.Equal(prev.Endpoints, r.EndpointIDs) {
		s.st.ACME.Applied = prev.Applied
	}
	for _, ep := range r.EndpointIDs {
		a := s.st.Endpoints[ep]
		s.st.Endpoints[ep] = assignment{Source: EndpointACME, CertificateID: a.CertificateID}
	}
	return s.save()
}

// RenewACME has cert-manager issue the endpoint's certificate again now.
func (s *Store) RenewACME(ctx context.Context, endpoint string) error {
	defer s.change()()
	a := s.st.ACME
	if a == nil || !slices.Contains(a.Endpoints, endpoint) {
		return codes.New(codes.TLSInvalid, "acme: the %s endpoint isn't using ACME", endpoint)
	}
	if ok, reason := s.acmeOK(); !ok {
		return codes.New(codes.TLSACMEUnavailable, "%s", reason)
	}
	names, err := s.acmeNames(ctx)
	if err != nil {
		return err
	}
	cfg, err := s.acmeConfig(a)
	if err != nil {
		return err
	}
	manifests, err := acme.Render(cfg, names, a.Renewal+1)
	if err != nil {
		return err
	}
	if err := s.o.ACME.Apply(ctx, manifests); err != nil {
		return fmt.Errorf("tls: the ACME stack can't be written: %w", err)
	}
	a.Renewal++
	s.o.Logger.Info("tls: acme renewal requested", log.F("endpoint", endpoint), log.F("renewal", a.Renewal))
	return s.save()
}

// SyncACME looks at what cert-manager has made and brings every ACME
// endpoint to it, through the same check and rollback as an assigned
// certificate. accessd calls it every minute. It returns what to audit.
func (s *Store) SyncACME(ctx context.Context) ([]ACMEEvent, error) {
	defer s.change()()
	a := s.st.ACME
	if a == nil || s.o.ACME == nil {
		return nil, nil
	}
	lg := s.o.Logger
	st, err := s.o.ACME.Status(ctx)
	if err != nil {
		lg.Warn("tls: cert-manager can't be read", log.F("error", err.Error()))
		return nil, err
	}
	var events []ACMEEvent
	failed := func(ep, msg string) {
		if msg == a.Failure {
			lg.Debug("tls: acme problem unchanged", log.F("endpoint", ep), log.F("reason", msg))
			return
		}
		a.Failure = msg
		lg.Warn("tls: acme problem", log.F("endpoint", ep), log.F("reason", msg))
		events = append(events, ACMEEvent{Kind: ACMEFailed, Endpoint: ep, Message: msg})
	}
	if st.Failure != "" {
		failed("", st.Failure)
	}
	if len(st.CertPEM) == 0 || len(st.KeyPEM) == 0 {
		lg.Debug("tls: cert-manager has issued nothing yet", log.F("ready", st.Ready))
		return events, s.save()
	}
	chain, err := parseCerts("issued certificate", string(st.CertPEM))
	if err != nil || len(chain) == 0 {
		failed("", "cert-manager's certificate doesn't parse")
		return events, s.save()
	}
	fp := Fingerprint(chain[0].Raw)
	if fp == a.Applied {
		if st.Failure == "" {
			a.Failure = ""
		}
		return events, s.save()
	}
	renewed := a.Applied != ""
	id, err := s.acmeCertificate(ctx, st, chain[0], chain[1:])
	if err != nil {
		failed("", sentence(err))
		return events, s.save()
	}
	ok := true
	for _, ep := range a.Endpoints {
		if s.st.Endpoints[ep].CertificateID == id {
			continue
		}
		if err := s.checkEndpoint(ep); err != nil {
			lg.Debug("tls: acme: the endpoint isn't ready", log.F("endpoint", ep), log.F("reason", sentence(err)))
			ok = false
			continue
		}
		if _, err := s.assign(ctx, ep, id); err != nil {
			ok = false
			failed(ep, sentence(err))
			continue
		}
		s.st.Endpoints[ep] = assignment{Source: EndpointACME, CertificateID: id}
		kind := ACMEIssued
		if renewed {
			kind = ACMERenewed
		}
		events = append(events, ACMEEvent{Kind: kind, Endpoint: ep, Fingerprint: fp, Expires: chain[0].NotAfter, Names: sanList(chain[0])})
		lg.Info("tls: acme certificate applied", log.F("endpoint", ep), log.F("kind", string(kind)), log.F("fingerprint", fp))
	}
	if ok {
		a.Applied = fp
		if st.Failure == "" {
			a.Failure = ""
		}
		s.pruneACME()
	}
	return events, s.save()
}

// acmeCertificate is the store id of the certificate cert-manager issued,
// added when it isn't there yet. No root is needed: the CA's own chain is
// what the CA sends, and the endpoint's check is the names, the key and the
// dates.
func (s *Store) acmeCertificate(ctx context.Context, st ACMEStatus, leaf *x509.Certificate, rest []*x509.Certificate) (string, error) {
	fp := Fingerprint(leaf.Raw)
	for _, sc := range s.st.Certificates {
		if sc.Source != SourceACME {
			continue
		}
		if c, err := s.view(sc); err == nil && c.Fingerprint == fp {
			return sc.ID, nil
		}
	}
	key, err := parseKey(string(st.KeyPEM))
	if err != nil {
		return "", err
	}
	kp, err := marshalKey(key)
	if err != nil {
		return "", err
	}
	c := candidate{leaf: leaf, chain: rest, pub: key.Public(), keyDesc: "the key cert-manager made", acme: true}
	cert, _, err := s.add(ctx, c, storedCert{Source: SourceACME}, kp...)
	if err != nil {
		return "", err
	}
	return cert.ID, nil
}

// pruneACME drops the ACME certificates no endpoint serves and its key.
func (s *Store) pruneACME() {
	used := map[string]bool{}
	for _, a := range s.assignments() {
		used[a.CertificateID] = true
	}
	keep := s.st.Certificates[:0]
	for _, sc := range s.st.Certificates {
		if sc.Source == SourceACME && !used[sc.ID] {
			if err := s.forget(sc.KeyItem); err != nil {
				s.o.Logger.Warn("tls: an old ACME key can't be wiped", log.F("id", sc.ID), log.F("error", err.Error()))
				keep = append(keep, sc)
				continue
			}
			s.o.Logger.Info("tls: old ACME certificate dropped", log.F("id", sc.ID))
			continue
		}
		keep = append(keep, sc)
	}
	s.st.Certificates = keep
}

// acmeLeave takes endpoint out of ACME because something else now serves
// it. When none is left the stack goes, the sealed tokens are wiped and the
// ACME certificates are dropped.
func (s *Store) acmeLeave(ctx context.Context, endpoint string) {
	a := s.st.ACME
	if a == nil || !slices.Contains(a.Endpoints, endpoint) {
		return
	}
	a.Endpoints = slices.DeleteFunc(a.Endpoints, func(e string) bool { return e == endpoint })
	if len(a.Endpoints) > 0 {
		return
	}
	lg := s.o.Logger
	if s.o.ACME != nil {
		if err := s.o.ACME.Remove(ctx); err != nil {
			lg.Warn("tls: the ACME stack can't be removed; it stays until the next change", log.F("error", err.Error()))
		}
	}
	for _, item := range []string{acmeTokenItem, acmeEABItem} {
		if err := s.forget(item); err != nil {
			lg.Warn("tls: a sealed ACME setting can't be wiped", log.F("item", item), log.F("error", err.Error()))
		}
	}
	s.st.ACME = nil
	s.pruneACME()
	lg.Info("tls: acme off: no endpoint uses it any more")
}

// decorateACME words an ACME endpoint's detail: waiting for the CA, or
// the problem the follower found.
func (s *Store) decorateACME(ep *Endpoint) {
	a := s.st.ACME
	if a == nil || ep.Source != EndpointACME {
		return
	}
	serving := false
	for _, sc := range s.st.Certificates {
		if sc.Source == SourceACME && sc.ID == ep.CertificateID {
			serving = true
		}
	}
	switch {
	case !serving && a.Failure != "":
		ep.Detail = "ACME: no certificate yet. " + a.Failure
	case serving && ep.State == StateExpiring:
		ep.Detail = strings.Replace(ep.Detail, "nothing renews it, so upload a new one", "cert-manager should have renewed it; check the renewal problem below or ask for a renewal now", 1)
		if a.Failure != "" {
			ep.Detail += " Renewal is failing: " + a.Failure
		}
	case !serving:
		ep.Detail = "ACME: waiting for the certificate authority to issue a certificate; the endpoint keeps what it serves until then."
	case a.Failure != "":
		ep.Detail += " Renewal is failing: " + a.Failure
	}
}
