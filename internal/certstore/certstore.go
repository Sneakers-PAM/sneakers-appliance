// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package certstore is the box's certificate store (spec 3, Section
// 2.7.1): certificates signed for a CSR made on the box or uploaded with
// their key, each with its chain, and which TLS endpoint serves which.
// Keys are KeyCustody sealed items, never in the store file. Assigning a
// certificate to :8443 swaps the files sneakers-osadmin serves, checks the
// swap with a handshake and puts the previous certificate back when the
// new one isn't served.
package certstore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Source is where a store certificate came from.
type Source string

// The sources.
const (
	SourceSelfSigned Source = "self-signed"
	SourceCSRSigned  Source = "csr-signed"
	SourceUploaded   Source = "uploaded"
)

// EndpointSource is where an endpoint's certificate comes from.
type EndpointSource string

// The endpoint sources: exactly one per endpoint.
const (
	EndpointSelfSigned EndpointSource = "self-signed"
	EndpointAssigned   EndpointSource = "assigned"
	EndpointACME       EndpointSource = "acme"
)

// State is an endpoint's certificate health.
type State string

// The states.
const (
	StateOK          State = "ok"
	StateSelfSigned  State = "self-signed"
	StateExpiring    State = "expiring"
	StateExpired     State = "expired"
	StateNames       State = "names-not-covered"
	StateUnavailable State = "unavailable"
)

// The endpoints.
const (
	EndpointAdmin   = "admin"
	EndpointProduct = "product"
)

// KeyType is the key GenerateCSR makes; RSA 4096 is the default.
type KeyType int

// The key types.
const (
	KeyRSA4096 KeyType = iota
	KeyRSA3072
	KeyECDSAP256
	KeyECDSAP384
)

// The store's limits, and how long before expiry warnings start.
const (
	maxCertificates = 32
	maxCSRs         = 8
	ExpiryWarning   = 30 * 24 * time.Hour
	// ProbeTimeout is how long the new certificate has to be served.
	ProbeTimeout = 15 * time.Second
	// selfSignedID is the box's own certificate's store id.
	selfSignedID = "self-signed"
)

// ACMEReason is why ACME isn't offered in this release.
const ACMEReason = "Not available yet: ACME through cert-manager comes with the product bundle."

// productReason is why the product endpoint can't be assigned yet.
const productReason = "Available when the product is installed."

// Sealer keeps the keys: init's KeyCustody on the box.
type Sealer interface {
	Seal(name string, secret []byte) error
	// Unseal returns the item; ok is false when it was never sealed.
	Unseal(name string) (secret []byte, ok bool, err error)
}

// Options wire a store.
type Options struct {
	// Dir is the store's own directory (root only).
	Dir string
	// AdminDir is sneakers-osadmin's directory, where :8443's tls.crt and
	// tls.key are served from.
	AdminDir string
	Sealer   Sealer
	// Names returns the box's management host name and addresses.
	Names func(context.Context) (host string, addrs []string, err error)
	// Probe checks :8443 serves the certificate with this fingerprint,
	// within ProbeTimeout; nil uses HandshakeProbe on the addresses.
	Probe func(ctx context.Context, fingerprint string) error
	// Own hands a file written into AdminDir to the osadmin user; nil
	// leaves it as written.
	Own    func(*os.File) error
	Now    func() time.Time
	Logger log.Logger
}

// Certificate is a store certificate.
type Certificate struct {
	ID     string
	Source Source
	Leaf   *x509.Certificate
	// Chain is the leaf first, to its root.
	Chain   []*x509.Certificate
	CSRID   string
	Added   time.Time
	UsedBy  []string
	KeyType string
	// Fingerprint is the leaf's SHA-256.
	Fingerprint string
	// PEM is the chain as PEM.
	PEM string
}

// CSR is a pending certificate request.
type CSR struct {
	ID, Subject, KeyType, PEM string
	Names                     []string
	Created                   time.Time
}

// Endpoint is a TLS listener the box hosts.
type Endpoint struct {
	ID, Name      string
	Available     bool
	Reason        string
	Source        EndpointSource
	CertificateID string
	Names         []string
	State         State
	Detail        string
	Serving       string
	Expires       time.Time
}

// ACMEState says whether ACME can be used.
type ACMEState struct {
	Available bool
	Reason    string
}

// Snapshot is the whole store as the page shows it.
type Snapshot struct {
	Certificates []Certificate
	CSRs         []CSR
	Endpoints    []Endpoint
	ACME         ACMEState
}

// CSRRequest is what GenerateCSR takes.
type CSRRequest struct {
	Names                                                  []string
	CommonName, Organization, OrganizationalUnit, Locality string
	Province, Country                                      string
	KeyType                                                KeyType
}

// ImportRequest is a key and certificate made elsewhere: PEM, or PKCS#12.
type ImportRequest struct {
	CertificatePEM, ChainPEM, KeyPEM string
	PKCS12                           []byte
	PKCS12Password                   string
	RootPEM                          string
}

// Store is the certificate store.
type Store struct {
	o  Options
	mu sync.Mutex
	st state
}

type state struct {
	Version      int                   `json:"version"`
	Certificates []storedCert          `json:"certificates"`
	CSRs         []storedCSR           `json:"csrs"`
	Endpoints    map[string]assignment `json:"endpoints"`
}

type storedCert struct {
	ID      string    `json:"id"`
	Source  Source    `json:"source"`
	PEM     string    `json:"pem"`
	KeyItem string    `json:"keyItem"`
	CSRID   string    `json:"csrId,omitempty"`
	Added   time.Time `json:"added"`
}

type storedCSR struct {
	ID      string    `json:"id"`
	PEM     string    `json:"pem"`
	KeyItem string    `json:"keyItem"`
	Names   []string  `json:"names"`
	Subject string    `json:"subject"`
	KeyType string    `json:"keyType"`
	Created time.Time `json:"created"`
}

type assignment struct {
	Source        EndpointSource `json:"source"`
	CertificateID string         `json:"certificateId,omitempty"`
}

const stateFile = "store.json"

// Open reads the store in o.Dir, or starts an empty one.
func Open(o Options) (*Store, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	s := &Store{o: o, st: state{Version: 1, Endpoints: map[string]assignment{}}}
	if o.Probe == nil {
		s.o.Probe = func(ctx context.Context, fp string) error {
			_, addrs, err := s.o.Names(ctx)
			if err != nil {
				return err
			}
			return HandshakeProbe(ctx, addrs, "8443", fp)
		}
	}
	b, err := os.ReadFile(filepath.Join(o.Dir, stateFile)) // #nosec G304 -- the store's own file
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("tls: %w", err)
	default:
		if err := json.Unmarshal(b, &s.st); err != nil {
			return nil, fmt.Errorf("tls: the store doesn't parse: %w", err)
		}
		if s.st.Endpoints == nil {
			s.st.Endpoints = map[string]assignment{}
		}
	}
	return s, nil
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(s.o.Dir, stateFile, b, nil)
}

// Snapshot returns the store, first recording the self-signed certificate
// :8443 serves when it is the box's own.
func (s *Store) Snapshot(ctx context.Context) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.captureSelfSigned(); err != nil {
		s.o.Logger.Warn("tls: the self-signed certificate can't be recorded", log.F("error", err.Error()))
	}
	host, addrs, err := s.o.Names(ctx)
	if err != nil {
		s.o.Logger.Warn("tls: the management names can't be read", log.F("error", err.Error()))
	}
	return s.snapshot(host, addrs), nil
}

func (s *Store) snapshot(host string, addrs []string) Snapshot {
	var out Snapshot
	for _, sc := range s.st.Certificates {
		c, err := s.view(sc)
		if err != nil {
			s.o.Logger.Warn("tls: a store certificate doesn't parse", log.F("id", sc.ID), log.F("error", err.Error()))
			continue
		}
		out.Certificates = append(out.Certificates, c)
	}
	for _, r := range s.st.CSRs {
		out.CSRs = append(out.CSRs, CSR{ID: r.ID, Subject: r.Subject, KeyType: r.KeyType, PEM: r.PEM, Names: slices.Clone(r.Names), Created: r.Created})
	}
	out.Endpoints = []Endpoint{s.adminEndpoint(host, addrs), {
		ID: EndpointProduct, Name: "Product (443)", Reason: productReason, State: StateUnavailable, Source: EndpointAssigned,
	}}
	out.ACME = ACMEState{Reason: ACMEReason}
	return out
}

func (s *Store) view(sc storedCert) (Certificate, error) {
	chain, err := parseCerts("store", sc.PEM)
	if err != nil {
		return Certificate{}, err
	}
	if len(chain) == 0 {
		return Certificate{}, errors.New("no certificate")
	}
	c := Certificate{ID: sc.ID, Source: sc.Source, Leaf: chain[0], Chain: chain, CSRID: sc.CSRID, Added: sc.Added, PEM: sc.PEM,
		KeyType: keyTypeName(chain[0].PublicKey), Fingerprint: Fingerprint(chain[0].Raw)}
	for id, a := range s.assignments() {
		if a.CertificateID == sc.ID {
			c.UsedBy = append(c.UsedBy, id)
		}
	}
	return c, nil
}

// assignments is every endpoint's source; the admin endpoint is
// self-signed until something else is assigned.
func (s *Store) assignments() map[string]assignment {
	out := map[string]assignment{EndpointAdmin: {Source: EndpointSelfSigned, CertificateID: selfSignedID}}
	for k, v := range s.st.Endpoints {
		out[k] = v
	}
	return out
}

func (s *Store) adminEndpoint(host string, addrs []string) Endpoint {
	a := s.assignments()[EndpointAdmin]
	ep := Endpoint{ID: EndpointAdmin, Name: ":8443 admin", Available: true, Source: a.Source, CertificateID: a.CertificateID, Names: boxNames(host, addrs)}
	leaf, err := readAdminLeaf(s.o.AdminDir)
	if err != nil {
		ep.State, ep.Detail = StateExpired, "The :8443 certificate can't be read: "+err.Error()
		return ep
	}
	ep.Serving, ep.Expires = Fingerprint(leaf.Raw), leaf.NotAfter
	now := s.o.Now()
	left := leaf.NotAfter.Sub(now)
	switch {
	case a.Source == EndpointSelfSigned:
		ep.State, ep.Detail = StateSelfSigned, "The box's own self-signed certificate; check its fingerprint."
	case left <= 0:
		ep.State, ep.Detail = StateExpired, fmt.Sprintf("The :8443 certificate expired on %s.", leaf.NotAfter.UTC().Format(time.DateOnly))
	case len(coveredNames(leaf, ep.Names)) == 0:
		ep.State, ep.Detail = StateNames, fmt.Sprintf("The :8443 certificate covers none of %s.", strings.Join(ep.Names, ", "))
	case left <= ExpiryWarning:
		ep.State, ep.Detail = StateExpiring, fmt.Sprintf("The :8443 certificate expires in %s (%s); nothing renews it, so upload a new one.", days(left), leaf.NotAfter.UTC().Format(time.DateOnly))
	default:
		ep.State, ep.Detail = StateOK, fmt.Sprintf("%s left.", days(left))
	}
	return ep
}

// boxNames are the names :8443 answers on: the host name, then the
// addresses.
func boxNames(host string, addrs []string) []string {
	var out []string
	if host != "" {
		out = append(out, host)
	}
	return append(out, addrs...)
}

// captureSelfSigned records the certificate :8443 serves while it is the
// box's own (sneakers-osadmin makes and renews it), sealing its key, so a
// revert can put it back.
func (s *Store) captureSelfSigned() error {
	if s.assignments()[EndpointAdmin].Source != EndpointSelfSigned {
		return nil
	}
	crt, key, err := readAdminFiles(s.o.AdminDir)
	if err != nil {
		return err
	}
	if i := s.find(selfSignedID); i >= 0 && s.st.Certificates[i].PEM == string(crt) {
		return nil
	}
	item := "tls-" + selfSignedID
	if err := s.o.Sealer.Seal(item, key); err != nil {
		return fmt.Errorf("tls: seal: %w", err)
	}
	sc := storedCert{ID: selfSignedID, Source: SourceSelfSigned, PEM: string(crt), KeyItem: item, Added: s.o.Now()}
	if i := s.find(selfSignedID); i >= 0 {
		s.st.Certificates[i] = sc
	} else {
		s.st.Certificates = append([]storedCert{sc}, s.st.Certificates...)
	}
	s.o.Logger.Info("tls: recorded the self-signed certificate", log.F("fingerprint", fingerprintPEM(crt)))
	return s.save()
}

func (s *Store) find(id string) int {
	return slices.IndexFunc(s.st.Certificates, func(c storedCert) bool { return c.ID == id })
}

func (s *Store) findCSR(id string) int {
	return slices.IndexFunc(s.st.CSRs, func(c storedCSR) bool { return c.ID == id })
}

var (
	dnsLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	countryRE  = regexp.MustCompile(`^[A-Z]{2}$`)
)

// checkName accepts a DNS name or an IP address for a CSR. Wildcards are
// refused before this: a wildcard certificate comes in with Upload PFX.
func checkName(n string) error {
	if net.ParseIP(n) != nil {
		return nil
	}
	name := n
	if len(name) > 253 || !strings.Contains(name, ".") && name != "localhost" {
		return codes.New(codes.TLSInvalid, "names: %q isn't a DNS name or an IP address", n)
	}
	for _, l := range strings.Split(name, ".") {
		if !dnsLabelRE.MatchString(l) {
			return codes.New(codes.TLSInvalid, "names: %q isn't a DNS name or an IP address", n)
		}
	}
	return nil
}

// GenerateCSR makes a key on the box, seals it and returns the CSR for
// the host name, the management addresses and the extra names.
func (s *Store) GenerateCSR(ctx context.Context, r CSRRequest) (CSR, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.st.CSRs) >= maxCSRs {
		return CSR{}, codes.New(codes.TLSLimit, "%d CSRs are already pending; discard one first", maxCSRs)
	}
	if r.Country != "" && !countryRE.MatchString(r.Country) {
		return CSR{}, codes.New(codes.TLSInvalid, "country: %q isn't a two-letter country code", r.Country)
	}
	host, addrs, err := s.o.Names(ctx)
	if err != nil {
		return CSR{}, err
	}
	var dns []string
	var ips []net.IP
	seen := map[string]bool{}
	add := func(n string) error {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || seen[n] {
			return nil
		}
		if err := checkName(n); err != nil {
			return err
		}
		seen[n] = true
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, n)
		}
		return nil
	}
	for _, n := range boxNames(host, addrs) {
		if err := add(n); err != nil {
			return CSR{}, err
		}
	}
	extra := 0
	for _, n := range r.Names {
		n = strings.ToLower(strings.TrimSpace(n))
		if strings.Contains(n, "*") {
			return CSR{}, codes.New(codes.TLSInvalid, "names: %q: a wildcard key is shared across servers; import it with Upload PFX", n)
		}
		if n == "" || seen[n] {
			continue
		}
		if extra++; extra > 1 {
			return CSR{}, codes.New(codes.TLSInvalid, "names: a request made on this box is for one name, plus the box's host name and addresses; for more names, import the certificate with Upload PFX")
		}
		if err := add(n); err != nil {
			return CSR{}, err
		}
	}
	if len(dns)+len(ips) == 0 {
		return CSR{}, codes.New(codes.TLSInvalid, "names: the box has no host name or management address yet")
	}
	cn := r.CommonName
	if cn == "" {
		cn = host
	}
	if cn == "" {
		cn = ips[0].String()
	}
	subj := pkix.Name{CommonName: cn}
	for _, f := range []struct {
		v   string
		dst *[]string
	}{{r.Organization, &subj.Organization}, {r.OrganizationalUnit, &subj.OrganizationalUnit}, {r.Locality, &subj.Locality}, {r.Province, &subj.Province}, {r.Country, &subj.Country}} {
		if v := strings.TrimSpace(f.v); v != "" {
			if len(v) > 64 {
				return CSR{}, codes.New(codes.TLSInvalid, "subject: %q is longer than 64 characters", v)
			}
			*f.dst = []string{v}
		}
	}
	var key crypto.Signer
	switch r.KeyType {
	case KeyRSA3072:
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	case KeyECDSAP256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyECDSAP384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyRSA4096:
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		return CSR{}, codes.New(codes.TLSInvalid, "key type: %d isn't one this box makes", r.KeyType)
	}
	if err != nil {
		return CSR{}, fmt.Errorf("tls: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subj, DNSNames: dns, IPAddresses: ips}, key)
	if err != nil {
		return CSR{}, fmt.Errorf("tls: %w", err)
	}
	id, err := newID()
	if err != nil {
		return CSR{}, err
	}
	kp, err := marshalKey(key)
	if err != nil {
		return CSR{}, err
	}
	item := "tls-" + id
	if err := s.o.Sealer.Seal(item, kp); err != nil {
		return CSR{}, fmt.Errorf("tls: seal: %w", err)
	}
	names := slices.Clone(dns)
	for _, ip := range ips {
		names = append(names, ip.String())
	}
	rec := storedCSR{ID: id, PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), KeyItem: item,
		Names: names, Subject: subj.String(), KeyType: keyTypeName(key.Public()), Created: s.o.Now()}
	s.st.CSRs = append(s.st.CSRs, rec)
	if err := s.save(); err != nil {
		return CSR{}, err
	}
	s.o.Logger.Info("tls: CSR generated", log.F("id", id), log.F("names", strings.Join(names, ",")), log.F("keyType", rec.KeyType))
	return CSR{ID: id, Subject: rec.Subject, KeyType: rec.KeyType, PEM: rec.PEM, Names: names, Created: rec.Created}, nil
}

// CompleteCSR validates a signed certificate against the pending CSR's
// key and stores it.
func (s *Store) CompleteCSR(ctx context.Context, id, certPEM, chainPEM, rootPEM string) (Certificate, []Check, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.findCSR(id)
	if i < 0 {
		return Certificate{}, nil, codes.New(codes.TLSUnknown, "no pending CSR has the id %q", id)
	}
	r := s.st.CSRs[i]
	blk, _ := pem.Decode([]byte(r.PEM))
	if blk == nil {
		return Certificate{}, nil, fmt.Errorf("tls: CSR %s doesn't parse", id)
	}
	req, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return Certificate{}, nil, fmt.Errorf("tls: CSR %s: %w", id, err)
	}
	certs, err := parseCerts("certificate", certPEM)
	if err != nil {
		return Certificate{}, nil, err
	}
	if len(certs) == 0 {
		return Certificate{}, nil, codes.New(codes.TLSFormat, "the signed certificate is missing")
	}
	chain, roots, err := chainAndRoots(certs[1:], chainPEM, rootPEM)
	if err != nil {
		return Certificate{}, nil, err
	}
	c := candidate{leaf: certs[0], chain: chain, roots: roots, pub: req.PublicKey, keyDesc: "the key CSR " + id + " was made with"}
	sc := storedCert{Source: SourceCSRSigned, KeyItem: r.KeyItem, CSRID: id}
	cert, checks, err := s.add(ctx, c, sc)
	if err != nil {
		return Certificate{}, checks, err
	}
	s.st.CSRs = slices.Delete(s.st.CSRs, i, i+1)
	if err := s.save(); err != nil {
		return Certificate{}, nil, err
	}
	return cert, checks, nil
}

// Import validates and stores a key and certificate made elsewhere. A
// PKCS#12 file is never kept; only its key (sealed) and chain are.
func (s *Store) Import(ctx context.Context, r ImportRequest) (Certificate, []Check, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var key crypto.Signer
	var leaf *x509.Certificate
	var extra []*x509.Certificate
	if len(r.PKCS12) > 0 {
		k, l, ch, err := parsePKCS12(r.PKCS12, r.PKCS12Password)
		if err != nil {
			return Certificate{}, nil, err
		}
		key, leaf, extra = k, l, ch
	} else {
		certs, err := parseCerts("certificate", r.CertificatePEM)
		if err != nil {
			return Certificate{}, nil, err
		}
		if len(certs) == 0 {
			return Certificate{}, nil, codes.New(codes.TLSFormat, "the certificate is missing")
		}
		if strings.TrimSpace(r.KeyPEM) == "" {
			return Certificate{}, nil, codes.New(codes.TLSFormat, "the private key is missing")
		}
		if key, err = parseKey(r.KeyPEM); err != nil {
			return Certificate{}, nil, err
		}
		leaf, extra = certs[0], certs[1:]
	}
	chain, roots, err := chainAndRoots(extra, r.ChainPEM, r.RootPEM)
	if err != nil {
		return Certificate{}, nil, err
	}
	c := candidate{leaf: leaf, chain: chain, roots: roots, pub: key.Public(), keyDesc: "the private key uploaded with it"}
	kp, err := marshalKey(key)
	if err != nil {
		return Certificate{}, nil, err
	}
	cert, checks, err := s.add(ctx, c, storedCert{Source: SourceUploaded}, kp...)
	if err != nil {
		return Certificate{}, checks, err
	}
	return cert, checks, s.save()
}

func chainAndRoots(extra []*x509.Certificate, chainPEM, rootPEM string) ([]*x509.Certificate, []*x509.Certificate, error) {
	chain, err := parseCerts("chain", chainPEM)
	if err != nil {
		return nil, nil, err
	}
	roots, err := parseCerts("root certificate", rootPEM)
	if err != nil {
		return nil, nil, err
	}
	return slices.Concat(extra, chain), roots, nil
}

// add validates c and appends it; key, when given, is sealed as a new item
// (an import), else sc.KeyItem already holds it (a CSR).
func (s *Store) add(ctx context.Context, c candidate, sc storedCert, key ...byte) (Certificate, []Check, error) {
	if len(s.st.Certificates) >= maxCertificates {
		return Certificate{}, nil, codes.New(codes.TLSLimit, "the store already holds %d certificates; delete one first", maxCertificates)
	}
	host, addrs, err := s.o.Names(ctx)
	if err != nil {
		return Certificate{}, nil, err
	}
	built, checks, err := validate(c, boxNames(host, addrs), s.o.Now())
	if err != nil {
		s.o.Logger.Info("tls: certificate refused", log.F("source", string(sc.Source)), log.F("reason", sentence(err)))
		return Certificate{}, checks, err
	}
	id, err := newID()
	if err != nil {
		return Certificate{}, nil, err
	}
	sc.ID, sc.PEM, sc.Added = id, encodeCerts(built), s.o.Now()
	if len(key) > 0 {
		sc.KeyItem = "tls-" + id
		if err := s.o.Sealer.Seal(sc.KeyItem, key); err != nil {
			return Certificate{}, nil, fmt.Errorf("tls: seal: %w", err)
		}
	}
	s.st.Certificates = append(s.st.Certificates, sc)
	cert, err := s.view(sc)
	if err != nil {
		return Certificate{}, nil, err
	}
	s.o.Logger.Info("tls: certificate stored", log.F("id", id), log.F("source", string(sc.Source)), log.F("fingerprint", cert.Fingerprint), log.F("expires", cert.Leaf.NotAfter))
	return cert, checks, nil
}

// DiscardCSR drops a pending CSR and its key.
func (s *Store) DiscardCSR(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.findCSR(id)
	if i < 0 {
		return codes.New(codes.TLSUnknown, "no pending CSR has the id %q", id)
	}
	if err := s.forget(s.st.CSRs[i].KeyItem); err != nil {
		return err
	}
	s.st.CSRs = slices.Delete(s.st.CSRs, i, i+1)
	s.o.Logger.Info("tls: CSR discarded", log.F("id", id))
	return s.save()
}

// Delete removes a certificate no endpoint uses.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.find(id)
	if i < 0 {
		return codes.New(codes.TLSUnknown, "no certificate has the id %q", id)
	}
	if id == selfSignedID {
		return codes.New(codes.TLSInUse, "the box's own self-signed certificate can't be deleted")
	}
	for ep, a := range s.assignments() {
		if a.CertificateID == id {
			return codes.New(codes.TLSInUse, "the %s endpoint uses this certificate; assign another one first", ep)
		}
	}
	if err := s.forget(s.st.Certificates[i].KeyItem); err != nil {
		return err
	}
	s.st.Certificates = slices.Delete(s.st.Certificates, i, i+1)
	s.o.Logger.Info("tls: certificate deleted", log.F("id", id))
	return s.save()
}

// forget overwrites a sealed key with nothing: KeyCustody has no delete.
func (s *Store) forget(item string) error {
	if item == "" {
		return nil
	}
	if err := s.o.Sealer.Seal(item, nil); err != nil {
		return fmt.Errorf("tls: seal: %w", err)
	}
	return nil
}

// Assign makes an endpoint serve a store certificate.
func (s *Store) Assign(ctx context.Context, endpoint, id string) (Endpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkEndpoint(endpoint); err != nil {
		return Endpoint{}, err
	}
	if id == selfSignedID {
		return s.revert(ctx)
	}
	if err := s.captureSelfSigned(); err != nil {
		return Endpoint{}, err
	}
	i := s.find(id)
	if i < 0 {
		return Endpoint{}, codes.New(codes.TLSUnknown, "no certificate has the id %q", id)
	}
	sc := s.st.Certificates[i]
	c, err := s.view(sc)
	if err != nil {
		return Endpoint{}, err
	}
	host, addrs, err := s.o.Names(ctx)
	if err != nil {
		return Endpoint{}, err
	}
	now := s.o.Now()
	if now.After(c.Leaf.NotAfter) {
		return Endpoint{}, codes.New(codes.TLSValidity, "the certificate expired on %s", c.Leaf.NotAfter.UTC().Format(time.DateOnly))
	}
	if names := boxNames(host, addrs); len(coveredNames(c.Leaf, names)) == 0 {
		return Endpoint{}, codes.New(codes.TLSNames, "the certificate covers %s only, not any of %s", strings.Join(sans(c.Leaf), ", "), strings.Join(names, ", "))
	}
	key, ok, err := s.o.Sealer.Unseal(sc.KeyItem)
	if err != nil {
		return Endpoint{}, fmt.Errorf("tls: unseal: %w", err)
	}
	if !ok || len(key) == 0 {
		return Endpoint{}, fmt.Errorf("tls: the key of certificate %s isn't sealed on this box", id)
	}
	if err := s.swap(ctx, []byte(sc.PEM), key, id, c.Fingerprint); err != nil {
		return Endpoint{}, err
	}
	s.st.Endpoints[endpoint] = assignment{Source: EndpointAssigned, CertificateID: id}
	if err := s.save(); err != nil {
		return Endpoint{}, err
	}
	s.o.Logger.Info("tls: certificate assigned", log.F("endpoint", endpoint), log.F("id", id), log.F("fingerprint", c.Fingerprint))
	return s.adminEndpoint(host, addrs), nil
}

// Revert puts an endpoint back on the box's own self-signed certificate:
// the one it served before, while it is still good for the box's names,
// or a new one.
func (s *Store) Revert(ctx context.Context, endpoint string) (Endpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkEndpoint(endpoint); err != nil {
		return Endpoint{}, err
	}
	return s.revert(ctx)
}

func (s *Store) revert(ctx context.Context) (Endpoint, error) {
	host, addrs, err := s.o.Names(ctx)
	if err != nil {
		return Endpoint{}, err
	}
	if s.assignments()[EndpointAdmin].Source == EndpointSelfSigned {
		return s.adminEndpoint(host, addrs), nil
	}
	crt, key, err := s.savedSelfSigned(host, addrs)
	if err != nil {
		return Endpoint{}, err
	}
	if crt == nil {
		if crt, key, err = NewSelfSigned(host, addrs, s.o.Now()); err != nil {
			return Endpoint{}, err
		}
	}
	if err := s.swap(ctx, crt, key, "", fingerprintPEM(crt)); err != nil {
		return Endpoint{}, err
	}
	delete(s.st.Endpoints, EndpointAdmin)
	if err := s.captureSelfSigned(); err != nil {
		return Endpoint{}, err
	}
	if err := s.save(); err != nil {
		return Endpoint{}, err
	}
	s.o.Logger.Info("tls: reverted to self-signed", log.F("endpoint", EndpointAdmin), log.F("fingerprint", fingerprintPEM(crt)))
	return s.adminEndpoint(host, addrs), nil
}

// savedSelfSigned returns the recorded self-signed certificate and key
// when it still has 30 days and names exactly the box's names, as
// sneakers-osadmin would keep it.
func (s *Store) savedSelfSigned(host string, addrs []string) ([]byte, []byte, error) {
	i := s.find(selfSignedID)
	if i < 0 {
		return nil, nil, nil
	}
	sc := s.st.Certificates[i]
	certs, err := parseCerts("store", sc.PEM)
	if err != nil || len(certs) == 0 {
		return nil, nil, nil //nolint:nilerr // a damaged record is replaced by a new certificate
	}
	leaf := certs[0]
	if !s.o.Now().Add(RenewBefore).Before(leaf.NotAfter) || !slices.Equal(sortedNames(sans(leaf)), sortedNames(boxNames(host, addrs))) {
		return nil, nil, nil
	}
	key, ok, err := s.o.Sealer.Unseal(sc.KeyItem)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: unseal: %w", err)
	}
	if !ok || len(key) == 0 {
		return nil, nil, nil
	}
	return []byte(sc.PEM), key, nil
}

func sortedNames(n []string) []string {
	out := slices.Clone(n)
	slices.Sort(out)
	return out
}

func (s *Store) checkEndpoint(endpoint string) error {
	switch endpoint {
	case EndpointAdmin:
		return nil
	case EndpointProduct:
		return codes.New(codes.TLSEndpointUnavailable, "the product endpoint is available when the product is installed")
	}
	return codes.New(codes.TLSUnknown, "no endpoint has the id %q", endpoint)
}

// swap writes the new :8443 files (marker names the store id, empty for
// self-signed), checks they're served, and puts the old files back if not.
func (s *Store) swap(ctx context.Context, crt, key []byte, id, fp string) error {
	prev, err := backupAdmin(s.o.AdminDir)
	if err != nil {
		return err
	}
	if err := s.writeAdmin(crt, key, id); err != nil {
		s.restore(prev)
		return err
	}
	pctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	start := time.Now()
	perr := s.o.Probe(pctx, fp)
	s.o.Logger.Debug("tls: :8443 self-test", log.F("fingerprint", fp), log.F("duration", time.Since(start).String()), log.F("ok", perr == nil))
	if perr != nil {
		s.restore(prev)
		s.o.Logger.Warn("tls: the new certificate wasn't served; the previous one is back", log.F("fingerprint", fp), log.F("error", perr.Error()))
		return codes.New(codes.TLSNotServed, ":8443 didn't serve the new certificate within %s (%v), so the previous one was put back", ProbeTimeout, perr)
	}
	return nil
}

func (s *Store) writeAdmin(crt, key []byte, id string) error {
	if err := writeFile(s.o.AdminDir, adminKey, key, s.o.Own); err != nil {
		return err
	}
	if err := writeFile(s.o.AdminDir, adminCert, crt, s.o.Own); err != nil {
		return err
	}
	if id == "" {
		if err := os.Remove(filepath.Join(s.o.AdminDir, AssignedMarker)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("tls: %w", err)
		}
		return nil
	}
	return writeFile(s.o.AdminDir, AssignedMarker, []byte(id+"\n"), s.o.Own)
}

func (s *Store) restore(prev adminFiles) {
	if err := s.writeAdmin(prev.crt, prev.key, prev.marker); err != nil {
		s.o.Logger.Error(err, "tls: the previous :8443 certificate can't be put back")
	}
}

func newID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("tls: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func fingerprintPEM(b []byte) string {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return ""
	}
	return Fingerprint(blk.Bytes)
}
