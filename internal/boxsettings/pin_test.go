// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxsettings

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// pinnedEmail is a relay at r with verification on and no CA.
func pinnedEmail(r *relay, mode string) Email {
	return Email{Host: "127.0.0.1", Port: r.port(), From: "no-reply@sneakers.example.org", Username: r.user, Password: r.pass, TLS: mode, Verify: true}
}

func leafOf(t *testing.T, r *relay) *x509.Certificate {
	t.Helper()
	c, err := r.certificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// A relay whose certificate the box doesn't trust stops the test before
// AUTH, STARTTLS or implicit TLS, and the refusal carries the certificate:
// its subject, issuer, validity dates and SHA-256 fingerprint.
func TestAnUntrustedRelayStopsBeforeAuth(t *testing.T) {
	for _, c := range []struct {
		name               string
		mode               string
		implicit, starttls bool
	}{
		{"starttls", TLSStartTLS, false, true},
		{"implicit tls", TLSImplicit, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRelay(t, c.implicit, c.starttls, "PLAIN")
			_, err := Send(context.Background(), pinnedEmail(r, c.mode), "admin@example.org")
			if !codes.Is(err, codes.EmailUntrusted) {
				t.Fatalf("want EMAIL_UNTRUSTED, got %v", err)
			}
			ce, ok := CertErrorOf(err)
			leaf := leafOf(t, r)
			if !ok || ce.Cert.Subject != "127.0.0.1" || ce.Cert.Issuer != "relay test CA" || ce.Cert.SHA256 != certstore.Fingerprint(leaf.Raw) ||
				!ce.Cert.NotBefore.Equal(leaf.NotBefore) || !ce.Cert.NotAfter.Equal(leaf.NotAfter) || ce.Pinned != "" || ce.Reason == "" {
				t.Fatalf("the refusal's certificate %+v (ok %v)", ce, ok)
			}
			if s := onlySession(t, r); s.authUser != "" || s.authMech != "" || s.from != "" {
				t.Fatalf("the relay got past TLS: %+v", s)
			}
		})
	}
}

// Pinned, the same relay passes with verification on: the presented
// certificate is checked against the pin, not the roots.
func TestAPinnedRelayPasses(t *testing.T) {
	r := newRelay(t, false, true, "PLAIN")
	e := pinnedEmail(r, TLSStartTLS)
	e.PinSHA256 = certstore.Fingerprint(leafOf(t, r).Raw)
	if !e.Encrypted() {
		t.Fatal("a pinned relay with verification on reads as unencrypted")
	}
	if _, err := Send(context.Background(), e, "admin@example.org"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if s := onlySession(t, r); !s.tls || s.authUser != r.user || s.rcpt != "admin@example.org" {
		t.Fatalf("session %+v", s)
	}
}

// A relay whose certificate changed fails before AUTH, with the old and
// the new fingerprints.
func TestAChangedCertificateFailsWithBothFingerprints(t *testing.T) {
	r := newRelay(t, true, false, "PLAIN")
	e := pinnedEmail(r, TLSImplicit)
	old := certstore.Fingerprint(leafOf(t, r).Raw)
	e.PinSHA256 = old
	next, _ := testCert(t)
	r.setCert(next)
	_, err := Send(context.Background(), e, "admin@example.org")
	if !codes.Is(err, codes.EmailPinMismatch) {
		t.Fatalf("want EMAIL_PIN_MISMATCH, got %v", err)
	}
	ce, ok := CertErrorOf(err)
	if !ok || ce.Pinned != old || ce.Cert.SHA256 != certstore.Fingerprint(leafOf(t, r).Raw) || ce.Cert.SHA256 == old {
		t.Fatalf("the refusal %+v", ce)
	}
	if !strings.Contains(err.Error(), old) || !strings.Contains(err.Error(), ce.Cert.SHA256) {
		t.Fatalf("the message doesn't name both: %v", err)
	}
	if s := onlySession(t, r); s.authUser != "" {
		t.Fatalf("authenticated to a changed relay: %+v", s)
	}
}

// A pinned certificate's validity dates still apply.
func TestAPinnedCertificatePastItsDatesFails(t *testing.T) {
	r := newRelay(t, false, true, "PLAIN")
	expired, _ := testCertFor(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	r.setCert(expired)
	e := pinnedEmail(r, TLSStartTLS)
	e.PinSHA256 = certstore.Fingerprint(leafOf(t, r).Raw)
	_, err := Send(context.Background(), e, "admin@example.org")
	if !codes.Is(err, codes.EmailUntrusted) || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("an expired pinned certificate: %v", err)
	}
	if ce, ok := CertErrorOf(err); !ok || ce.Pinned != e.PinSHA256 {
		t.Fatalf("the refusal %+v", ce)
	}
}

// With verification off the CA isn't used, so a bad stored one neither
// fails the check nor the send.
func TestVerifyOffIgnoresAStoredCA(t *testing.T) {
	r := newRelay(t, false, true, "PLAIN")
	e := pinnedEmail(r, TLSStartTLS)
	e.Verify, e.CA = false, "not a certificate"
	if err := e.Check(); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if _, err := Send(context.Background(), e, "admin@example.org"); err != nil {
		t.Fatalf("Send: %v", err)
	}
}

// A pin is a SHA-256 fingerprint, kept in the colon form; any other form
// is refused.
func TestAPinIsAFingerprint(t *testing.T) {
	e := relayEmail()
	e.PinSHA256 = strings.Repeat("AB:", 31) + "AB"
	if err := e.Check(); err != nil {
		t.Fatalf("a colon fingerprint: %v", err)
	}
	for _, bad := range []string{"AB:CD", strings.Repeat("ab", 32), strings.Repeat("ZZ:", 31) + "ZZ"} {
		e.PinSHA256 = bad
		if err := e.Check(); !codes.Is(err, codes.EmailInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// A failed send names its step and the relay's reply, without the
// password.
func TestAFailedSendNamesTheStepAndReply(t *testing.T) {
	r := newRelay(t, false, false, "PLAIN")
	e := Email{Host: "127.0.0.1", Port: r.port(), From: "no-reply@sneakers.example.org", Username: r.user, TLS: TLSNone}
	e.Password = r.pass + "-not"
	_, err := Send(context.Background(), e, "admin@example.org")
	step, reply := FailureOf(err)
	if step != StepAuth || !strings.Contains(reply, "535") || strings.Contains(reply, e.Password) {
		t.Fatalf("step %q reply %q (%v)", step, reply, err)
	}
	r2 := newRelay(t, false, true, "PLAIN")
	_, err = Send(context.Background(), pinnedEmail(r2, TLSStartTLS), "admin@example.org")
	if step, _ := FailureOf(err); step != StepTLS {
		t.Fatalf("an untrusted relay's step %q", step)
	}
}
