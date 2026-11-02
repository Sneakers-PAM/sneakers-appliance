// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxsettings

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// RelayCert is the certificate a relay presented, as the Email page shows
// it for checking against one got another way.
type RelayCert struct {
	Subject   string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	// SHA256 is the fingerprint, as certstore.Fingerprint gives it.
	SHA256   string
	DNSNames []string
	IPs      []string
}

func relayCertOf(c *x509.Certificate) RelayCert {
	out := RelayCert{Subject: nameOf(c.Subject.CommonName, c.Subject.String()), Issuer: nameOf(c.Issuer.CommonName, c.Issuer.String()),
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, SHA256: certstore.Fingerprint(c.Raw), DNSNames: c.DNSNames}
	for _, ip := range c.IPAddresses {
		out.IPs = append(out.IPs, ip.String())
	}
	return out
}

func nameOf(cn, full string) string {
	if cn != "" {
		return cn
	}
	return full
}

// CertError is a relay certificate the box refused before AUTH: one it
// doesn't trust, or not the pinned one.
type CertError struct {
	Cert RelayCert
	// Pinned is the pin it was held to; empty when there is none.
	Pinned string
	// Reason says why it was refused.
	Reason string
	// mismatch is a pinned relay that presented another certificate.
	mismatch bool
}

func (e *CertError) Error() string {
	if e.mismatch {
		return fmt.Sprintf("the relay presented %s (%s, issued by %s), not the pinned %s", e.Cert.SHA256, e.Cert.Subject, e.Cert.Issuer, e.Pinned)
	}
	return fmt.Sprintf("the relay's certificate %s (%s, issued by %s) isn't trusted: %s", e.Cert.SHA256, e.Cert.Subject, e.Cert.Issuer, e.Reason)
}

// coded is e under its code, EMAIL_PIN_MISMATCH or EMAIL_UNTRUSTED.
func (e *CertError) coded() error {
	if e.mismatch {
		return codes.Wrap(codes.EmailPinMismatch, e)
	}
	return codes.Wrap(codes.EmailUntrusted, e)
}

// Untrusted is the EMAIL_UNTRUSTED refusal of cert, for reason; pinned
// is the pin it was held to, if any.
func Untrusted(cert RelayCert, pinned, reason string) error {
	return (&CertError{Cert: cert, Pinned: pinned, Reason: reason}).coded()
}

// PinMismatch is the EMAIL_PIN_MISMATCH refusal of cert, presented in
// place of the pinned certificate.
func PinMismatch(cert RelayCert, pinned string) error {
	return (&CertError{Cert: cert, Pinned: pinned, Reason: "not the pinned certificate", mismatch: true}).coded()
}

// CertErrorOf is the refused certificate err carries.
func CertErrorOf(err error) (*CertError, bool) { return certErrorIn(err) }

func certErrorIn(err error) (*CertError, bool) {
	var ce *CertError
	if errors.As(err, &ce) {
		return ce, true
	}
	return nil, false
}

// verifyRelay checks the relay's certificate: against pin when there is
// one (the leaf must be it, within its dates), else as Go's own
// verification would, against roots (nil for the system roots) for host.
func verifyRelay(cs tls.ConnectionState, host, pin string, roots *x509.CertPool, now time.Time) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("the relay presented no certificate")
	}
	leaf := cs.PeerCertificates[0]
	if pin != "" {
		if fp := certstore.Fingerprint(leaf.Raw); fp != pin {
			return &CertError{Cert: relayCertOf(leaf), Pinned: pin, Reason: "not the pinned certificate", mismatch: true}
		}
		switch {
		case now.Before(leaf.NotBefore):
			return &CertError{Cert: relayCertOf(leaf), Pinned: pin, Reason: "the pinned certificate isn't valid until " + leaf.NotBefore.UTC().Format(time.RFC3339)}
		case now.After(leaf.NotAfter):
			return &CertError{Cert: relayCertOf(leaf), Pinned: pin, Reason: "the pinned certificate expired at " + leaf.NotAfter.UTC().Format(time.RFC3339)}
		}
		return nil
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter, CurrentTime: now}); err != nil {
		return &CertError{Cert: relayCertOf(leaf), Reason: err.Error()}
	}
	return nil
}

// Presented is the certificate the relay in e presents now, over its TLS
// mode, checking nothing and sending no AUTH or mail: what a pin is
// confirmed against.
func Presented(ctx context.Context, e Email) (RelayCert, error) {
	if !e.Configured() {
		return RelayCert{}, codes.New(codes.EmailInvalid, "no relay is set")
	}
	if e.TLS != TLSStartTLS && e.TLS != TLSImplicit {
		return RelayCert{}, codes.New(codes.EmailInvalid, "the relay is reached without TLS; there's no certificate to pin")
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	var leaf *x509.Certificate
	// #nosec G402 -- nothing is sent; the certificate is only read, for the
	// admin to check and pin.
	cfg := &tls.Config{ServerName: e.Host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, //nolint:gosec
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the relay presented no certificate")
			}
			leaf = cs.PeerCertificates[0]
			return nil
		}}
	addr := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return RelayCert{}, sendFailed(StepConnect, "the relay "+addr+" can't be reached", err)
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if e.TLS == TLSImplicit {
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return RelayCert{}, sendFailed(StepTLS, "TLS with the relay failed", err)
		}
		_ = tc.Close()
	} else {
		c, err := smtp.NewClient(conn, e.Host)
		if err != nil {
			return RelayCert{}, sendFailed(StepConnect, "the relay didn't greet", err)
		}
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return RelayCert{}, failedAt(StepTLS, "no STARTTLS in the relay's EHLO", codes.New(codes.EmailSend, "the relay doesn't offer STARTTLS"))
		}
		if err := c.StartTLS(cfg); err != nil {
			return RelayCert{}, sendFailed(StepTLS, "STARTTLS with the relay failed", err)
		}
		_ = c.Quit()
	}
	if leaf == nil {
		return RelayCert{}, codes.New(codes.EmailSend, "the relay presented no certificate")
	}
	return relayCertOf(leaf), nil
}
