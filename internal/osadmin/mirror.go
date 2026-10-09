// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// The internal update mirror (docs/update-mirror.md): an http:// or
// https:// source in the update policy. An https:// mirror is checked
// against the system roots plus the update trust's private CAs, and the
// trust's optional pin, always by Go's own verification. A .bin is
// verified by its signature whatever the transport.
package osadmin

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

const (
	// updateTrustFile is the update trust, in Paths.APIDir.
	updateTrustFile = "update-trust.json"
	// maxTrustPEM and maxTrustCAs bound what an owner may paste.
	maxTrustPEM = 64 << 10
	maxTrustCAs = 8
	httpNote    = "plain HTTP: integrity from the signature only"
)

// updateTrust is the update trust as stored: PEM CA certificates and a pin
// in colon hex, either may be empty.
type updateTrust struct {
	CAPEM string    `json:"caPem,omitempty"`
	Pin   string    `json:"pin,omitempty"`
	SetBy string    `json:"setBy"`
	SetAt time.Time `json:"setAt"`
}

// mirrorCheck is the last mirror fetch, for GetUpgrades.
type mirrorCheck struct {
	mu         sync.Mutex
	base       string
	at         time.Time
	err        error
	peer       *x509.Certificate
	pinMatched bool
}

// validMirror reports whether u may be the policy's mirror: http or https,
// a host, no credentials, no query or fragment.
func validMirror(u string) bool {
	p, err := url.Parse(u)
	return err == nil && (p.Scheme == "http" || p.Scheme == "https") && p.Host != "" && p.User == nil && p.RawQuery == "" && !p.ForceQuery && p.Fragment == ""
}

// readTrust reads the update trust; ok is false when none is set.
func (s *Server) readTrust() (updateTrust, bool, error) {
	b, err := os.ReadFile(s.ownPath(updateTrustFile)) // #nosec G304 -- osadmin's own file
	if errors.Is(err, os.ErrNotExist) {
		return updateTrust{}, false, nil
	}
	if err != nil {
		return updateTrust{}, false, err
	}
	var t updateTrust
	if err := json.Unmarshal(b, &t); err != nil {
		return updateTrust{}, false, fmt.Errorf("the update trust doesn't parse: %w", err)
	}
	return t, true, nil
}

// parseTrustCAs reads PEM CA certificates: each must be a CA (basic
// constraints CA:TRUE) and valid at now.
func parseTrustCAs(s string, now time.Time) ([]*x509.Certificate, error) {
	rest := []byte(strings.TrimSpace(s))
	if len(rest) > maxTrustPEM {
		return nil, codes.New(codes.TLSInvalid, "ca_pem: at most %d bytes", maxTrustPEM)
	}
	var out []*x509.Certificate
	for len(rest) > 0 {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			if len(out) == 0 || len(strings.TrimSpace(string(rest))) > 0 {
				return nil, codes.New(codes.TLSFormat, "ca_pem: not PEM certificates")
			}
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, codes.New(codes.TLSFormat, "ca_pem: a %s block; only CERTIFICATE blocks are taken", blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, codes.New(codes.TLSFormat, "ca_pem: a certificate doesn't parse: %v", err)
		}
		if !c.IsCA || !c.BasicConstraintsValid {
			return nil, codes.New(codes.TLSUsage, "ca_pem: %q isn't a CA certificate (basic constraints CA:TRUE)", subjectName(c))
		}
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return nil, codes.New(codes.TLSValidity, "ca_pem: %q is valid from %s to %s", subjectName(c), c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339))
		}
		out = append(out, c)
		rest = []byte(strings.TrimSpace(string(rest)))
	}
	if len(out) > maxTrustCAs {
		return nil, codes.New(codes.TLSInvalid, "ca_pem: at most %d certificates", maxTrustCAs)
	}
	return out, nil
}

// normalizePin folds a SHA-256 fingerprint in any common form (colons or
// spaces, any case) to the colon hex Fingerprint gives.
func normalizePin(s string) (string, error) {
	h := strings.Map(func(r rune) rune {
		if r == ':' || unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToLower(r)
	}, s)
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != sha256.Size {
		return "", codes.New(codes.TLSInvalid, "pin_sha256: a SHA-256 fingerprint is 64 hex digits")
	}
	h = strings.ToUpper(h)
	parts := make([]string, 0, sha256.Size)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":"), nil
}

func subjectName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

func issuerOf(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		return c.Issuer.CommonName
	}
	return c.Issuer.String()
}

// pinError is a mirror certificate that chained but isn't the pinned one.
type pinError struct{ cert *x509.Certificate }

func (e *pinError) Error() string {
	return "the server certificate " + Fingerprint(e.cert.Raw) + " isn't the pinned one"
}

// fetchClient is the client for src. The release source is checked
// against the system roots alone; the mirror against those plus the update
// trust, and the trust's pin. Tests may set UpgradeOptions.HTTPClient,
// which then serves every source.
func (s *Server) fetchClient(src source) (*http.Client, error) {
	if hc := s.o.Upgrade.HTTPClient; hc != nil {
		return hc, nil
	}
	roots := s.o.Upgrade.SystemRoots
	if roots == nil {
		var err error
		if roots, err = x509.SystemCertPool(); err != nil {
			s.o.Logger.Warn("osadmin: the system roots don't load; only the update trust's CAs are trusted", log.F("error", err.Error()))
			roots = x509.NewCertPool()
		}
	} else {
		roots = roots.Clone()
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	if src.name == "mirror" {
		t, _, err := s.readTrust()
		if err != nil {
			return nil, codes.New(codes.UpgradeMirrorUntrusted, "%v; set the update trust again", err)
		}
		cas, err := parseTrustCAs(t.CAPEM, s.o.Clock.Now())
		if err != nil {
			return nil, codes.New(codes.UpgradeMirrorUntrusted, "the update trust's CA isn't usable: %s", describe(err))
		}
		for _, c := range cas {
			roots.AddCert(c)
		}
		if pin := t.Pin; pin != "" {
			cfg.VerifyConnection = func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 || Fingerprint(cs.PeerCertificates[0].Raw) != pin {
					return &pinError{cert: cs.PeerCertificates[0]}
				}
				return nil
			}
		}
	}
	return &http.Client{
		Timeout:   time.Hour,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: cfg},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != via[0].URL.Scheme {
				return fmt.Errorf("a redirect from %s to %s is refused", via[0].URL.Scheme, req.URL.Scheme)
			}
			return nil
		},
	}, nil
}

// open starts a GET of src's URL. It returns the 200 response, and the
// server certificate it was presented with, refused or not.
func (s *Server) open(ctx context.Context, src source, what string) (*http.Response, *x509.Certificate, error) {
	hc, err := s.fetchClient(src)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.url, nil)
	if err != nil {
		return nil, nil, codes.Wrap(codes.UpgradeUpload, err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		peer, ferr := s.refusal(src, what, err)
		return nil, peer, ferr
	}
	var peer *x509.Certificate
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		peer = resp.TLS.PeerCertificates[0]
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, peer, codes.New(codes.UpgradeUpload, "the %s answered %s for the %s", src.name, resp.Status, what)
	}
	return resp, peer, nil
}

// refusal turns a failed request into its coded error: a mirror
// certificate that isn't trusted or isn't the pinned one, naming what was
// presented, or the source not answering.
func (s *Server) refusal(src source, what string, err error) (*x509.Certificate, error) {
	var pe *pinError
	if errors.As(err, &pe) {
		t, _, _ := s.readTrust()
		return pe.cert, codes.New(codes.UpgradeMirrorPin, "the mirror presented %s (issued by %s), not the pinned %s", Fingerprint(pe.cert.Raw), issuerOf(pe.cert), t.Pin)
	}
	var ve *tls.CertificateVerificationError
	if errors.As(err, &ve) && len(ve.UnverifiedCertificates) > 0 {
		c := ve.UnverifiedCertificates[0]
		if src.name == "mirror" {
			return c, codes.New(codes.UpgradeMirrorUntrusted, "the mirror's certificate %s (%s, issued by %s) isn't trusted: %v; add its CA as the update trust on Certificates", Fingerprint(c.Raw), subjectName(c), issuerOf(c), ve.Err)
		}
		return c, codes.New(codes.UpgradeUpload, "the %s's certificate isn't trusted: %v", src.name, ve.Err)
	}
	return nil, codes.New(codes.UpgradeUpload, "the %s didn't answer for the %s: %v", src.name, what, err)
}

// fetched logs and audits one fetch attempt, and for the mirror records it
// for GetUpgrades.
func (s *Server) fetched(ctx context.Context, src source, what string, peer *x509.Certificate, started time.Time, n int64, err error) {
	ms := time.Since(started).Milliseconds()
	result := "ok"
	if err != nil {
		result = symbolOf(err)
	}
	fields := []log.Field{log.F("url", src.url), log.F("source", src.name), log.F("what", what), log.F("result", result), log.F("ms", ms), log.F("bytes", n)}
	if err != nil {
		s.o.Logger.Warn("osadmin: update fetch failed", append(fields, log.F("error", describe(err)))...)
	} else {
		s.o.Logger.Info("osadmin: update fetch", fields...)
	}
	c := callFrom(ctx)
	s.write(osaudit.Entry{Actor: c.session.Admin, Source: c.source, Action: "upgrade.source.fetch", Target: src.url,
		Detail: map[string]string{"source": src.name, "what": what, "ms": strconv.FormatInt(ms, 10), "bytes": strconv.FormatInt(n, 10)}}, err)
	if src.name != "mirror" {
		return
	}
	pinMatched := false
	if t, _, _ := s.readTrust(); t.Pin != "" && peer != nil {
		pinMatched = Fingerprint(peer.Raw) == t.Pin
	}
	s.mirror.mu.Lock()
	defer s.mirror.mu.Unlock()
	s.mirror.base, s.mirror.at, s.mirror.err, s.mirror.peer, s.mirror.pinMatched = s.policy().MirrorURL, s.o.Clock.Now(), err, peer, pinMatched
}

// forgetMirrorCheck drops the last mirror fetch when what it was checked
// against changes.
func (s *Server) forgetMirrorCheck() {
	s.mirror.mu.Lock()
	defer s.mirror.mu.Unlock()
	s.mirror.base, s.mirror.peer, s.mirror.err = "", nil, nil
}

// mirrorStatus is GetUpgrades' view of the mirror; nil with none set.
func (s *Server) mirrorStatus(p Policy) *osadminv1.MirrorStatus {
	if p.MirrorURL == "" {
		return nil
	}
	out := &osadminv1.MirrorStatus{Scheme: "https"}
	if strings.HasPrefix(p.MirrorURL, "http://") {
		out.Scheme, out.Note = "http", httpNote
	}
	t, set, err := s.readTrust()
	if err != nil {
		s.o.Logger.Error(err, "osadmin: the update trust doesn't read")
	}
	if out.Scheme == "https" {
		out.CustomCa, out.Pinned = set && t.CAPEM != "", set && t.Pin != ""
		out.Note = "HTTPS, checked against the system roots"
		if out.CustomCa {
			out.Note += " and the update trust's CA"
		}
		if out.Pinned {
			out.Note += ", with the server certificate pinned"
		}
	}
	s.mirror.mu.Lock()
	defer s.mirror.mu.Unlock()
	if s.mirror.base != p.MirrorURL || s.mirror.at.IsZero() {
		return out
	}
	out.Checked, out.CheckedAt, out.Ok = true, timestamppb.New(s.mirror.at), s.mirror.err == nil
	if s.mirror.err != nil {
		out.Code, out.Error = symbolOf(s.mirror.err), describe(s.mirror.err)
	}
	if c := s.mirror.peer; c != nil {
		out.ServerSubject, out.ServerIssuer, out.ServerNotAfter, out.ServerSha256 = subjectName(c), issuerOf(c), timestamppb.New(c.NotAfter), Fingerprint(c.Raw)
		out.PinMatched = s.mirror.pinMatched
	}
	return out
}

// trustToWire is the update trust as the Certificates page shows it,
// with every CA, an expired one too.
func trustToWire(t updateTrust) *osadminv1.UpdateTrust {
	out := &osadminv1.UpdateTrust{PinSha256: t.Pin, SetBy: t.SetBy, SetAt: timestamppb.New(t.SetAt)}
	var cas []*x509.Certificate
	for rest := []byte(t.CAPEM); ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			cas = append(cas, c)
		}
	}
	for _, c := range cas {
		out.Cas = append(out.Cas, &osadminv1.TrustedCa{Subject: subjectName(c), Issuer: issuerOf(c), NotAfter: timestamppb.New(c.NotAfter), Sha256: Fingerprint(c.Raw)})
	}
	return out
}

// SetUpdateTrust replaces the update trust: the private CAs an https://
// mirror may chain to, for the mirror's fetches only, and an optional pin.
func (h *tlsSvc) SetUpdateTrust(ctx context.Context, r *connect.Request[osadminv1.SetUpdateTrustRequest]) (*connect.Response[osadminv1.SetUpdateTrustResponse], error) {
	s, c := h.s, callFrom(ctx)
	now := s.o.Clock.Now()
	t := updateTrust{CAPEM: strings.TrimSpace(r.Msg.GetCaPem()), SetBy: c.session.Admin, SetAt: now.UTC()}
	c.note("update trust")
	if t.CAPEM == "" && strings.TrimSpace(r.Msg.GetPinSha256()) == "" {
		return nil, codes.New(codes.TLSInvalid, "give a CA (PEM), a pin, or both; ClearUpdateTrust removes the trust")
	}
	cas, err := parseTrustCAs(t.CAPEM, now)
	if err != nil {
		return nil, err
	}
	if p := strings.TrimSpace(r.Msg.GetPinSha256()); p != "" {
		if t.Pin, err = normalizePin(p); err != nil {
			return nil, err
		}
	}
	fps := make([]string, 0, len(cas))
	for _, ca := range cas {
		fps = append(fps, Fingerprint(ca.Raw))
	}
	c.note("update trust", "cas", strings.Join(fps, ","), "pin", t.Pin)
	b, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.o.Paths.APIDir(), 0o700); err != nil {
		return nil, err
	}
	if err := writeAtomic(s.ownPath(updateTrustFile), b); err != nil {
		return nil, err
	}
	s.forgetMirrorCheck()
	s.o.Logger.Info("osadmin: update trust set", log.F("cas", len(cas)), log.F("pinned", t.Pin != ""), log.F("by", t.SetBy))
	return connect.NewResponse(&osadminv1.SetUpdateTrustResponse{UpdateTrust: trustToWire(t)}), nil
}

// ClearUpdateTrust removes the update trust.
func (h *tlsSvc) ClearUpdateTrust(ctx context.Context, _ *connect.Request[osadminv1.ClearUpdateTrustRequest]) (*connect.Response[osadminv1.ClearUpdateTrustResponse], error) {
	s := h.s
	callFrom(ctx).note("update trust")
	if err := os.Remove(s.ownPath(updateTrustFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s.forgetMirrorCheck()
	s.o.Logger.Info("osadmin: update trust cleared", log.F("by", callFrom(ctx).session.Admin))
	return connect.NewResponse(&osadminv1.ClearUpdateTrustResponse{}), nil
}

// updateTrustWire is GetCertificateStore's update_trust; nil with none set.
func (s *Server) updateTrustWire() *osadminv1.UpdateTrust {
	t, set, err := s.readTrust()
	if err != nil {
		s.o.Logger.Error(err, "osadmin: the update trust doesn't read")
	}
	if !set {
		return nil
	}
	return trustToWire(t)
}
