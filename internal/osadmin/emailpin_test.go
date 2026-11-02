// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsettings"
)

var (
	pinA = strings.TrimSuffix(strings.Repeat("AA:", 32), ":")
	pinB = strings.TrimSuffix(strings.Repeat("BB:", 32), ":")
)

func relayCert(sha string) boxsettings.RelayCert {
	return boxsettings.RelayCert{Subject: "relay.example.org", Issuer: "relay.example.org", NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), SHA256: sha, DNSNames: []string{"relay.example.org"}}
}

// pinBox is an email box whose relay presents the certificate presented
// holds.
func pinBox(t *testing.T, presented *string) *emailBox {
	t.Helper()
	e := newEmailBox(t, emailYAML)
	e.setPresented(func(_ context.Context, m boxsettings.Email) (boxsettings.RelayCert, error) {
		if m.Host != "relay.example.org" {
			return boxsettings.RelayCert{}, errors.New("not the relay")
		}
		return relayCert(*presented), nil
	})
	e.alice.stepUp("alice")
	return e
}

func refusalDetail(t *testing.T, err error) *osadminv1.EmailCertificateRefusal {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("not a connect error: %v", err)
	}
	for _, d := range ce.Details() {
		if m, derr := d.Value(); derr == nil {
			if r, ok := m.(*osadminv1.EmailCertificateRefusal); ok {
				return r
			}
		}
	}
	t.Fatalf("no EmailCertificateRefusal on %v", err)
	return nil
}

// A test that meets a certificate the box doesn't trust answers
// EMAIL_UNTRUSTED with the certificate, and its audit entry says where it
// stopped and why.
func TestAnUntrustedRelayAnswersWithItsCertificate(t *testing.T) {
	presented := pinA
	e := pinBox(t, &presented)
	e.sendErr = boxsettings.Untrusted(relayCert(pinA), "", "x509: certificate signed by unknown authority")
	pass := relayPassword
	_, err := e.client(e.alice).SendTestEmail(context.Background(), connect.NewRequest(&osadminv1.SendTestEmailRequest{To: "admin@example.org", Settings: relaySettings(), Password: &pass}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "EMAIL_UNTRUSTED")
	r := refusalDetail(t, err)
	c := r.GetCertificate()
	if c.GetSha256() != pinA || c.GetSubject() != "relay.example.org" || c.GetIssuer() != "relay.example.org" || c.GetNotBefore() == nil || c.GetNotAfter() == nil ||
		len(c.GetDnsNames()) != 1 || r.GetPinnedSha256() != "" || !strings.Contains(r.GetReason(), "unknown authority") {
		t.Fatalf("the refusal %v", r)
	}
	a := lastEntry(t, e.log, "product.email.test-send")
	if a.Outcome == "ok" || a.Detail["step"] != boxsettings.StepTLS || !strings.Contains(a.Detail["reply"], "unknown authority") {
		t.Fatalf("audit %+v", a)
	}
}

// A changed certificate answers EMAIL_PIN_MISMATCH with the old and new
// fingerprints.
func TestAChangedRelayCertificateAnswersBothFingerprints(t *testing.T) {
	presented := pinB
	e := pinBox(t, &presented)
	e.sendErr = boxsettings.PinMismatch(relayCert(pinB), pinA)
	s := relaySettings()
	s.PinSha256 = pinA
	_, err := e.client(e.alice).SendTestEmail(context.Background(), connect.NewRequest(&osadminv1.SendTestEmailRequest{To: "admin@example.org", Settings: s}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "EMAIL_PIN_MISMATCH")
	if r := refusalDetail(t, err); r.GetPinnedSha256() != pinA || r.GetCertificate().GetSha256() != pinB {
		t.Fatalf("the refusal %v", r)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.sent) != 1 || e.sent[0].PinSHA256 != pinA {
		t.Fatalf("the test didn't carry the form's pin: %+v", e.sent)
	}
}

// Pinning checks the relay presents that certificate now, and answers the
// form's settings with the pin and verification on; it saves nothing and
// is audited.
func TestPinningTheRelayCertificate(t *testing.T) {
	presented := pinA
	e := pinBox(t, &presented)
	ctx := context.Background()
	s := relaySettings()
	s.Verify = false
	typed := strings.ToLower(strings.ReplaceAll(pinA, ":", ""))
	r, err := e.client(e.alice).PinEmailCertificate(ctx, connect.NewRequest(&osadminv1.PinEmailCertificateRequest{Settings: s, Sha256: typed}))
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Msg.GetSettings(); got.GetPinSha256() != pinA || !got.GetVerify() || got.GetHost() != "relay.example.org" || r.Msg.GetCertificate().GetSha256() != pinA {
		t.Fatalf("pinned %v", r.Msg)
	}
	a := lastEntry(t, e.log, "product.email.pin")
	if a.Outcome != "ok" || a.Detail["pinAdded"] != pinA || a.Detail["pinRemoved"] != "" || a.Detail["host"] != "relay.example.org" {
		t.Fatalf("audit %+v", a)
	}
	if saved, _ := e.settings.Email(); saved.PinSHA256 != "" {
		t.Fatalf("pinning saved the settings: %+v", saved)
	}
	presented = pinB
	_, err = e.client(e.alice).PinEmailCertificate(ctx, connect.NewRequest(&osadminv1.PinEmailCertificateRequest{Settings: s, Sha256: pinA}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "EMAIL_PIN_MISMATCH")
	_, err = e.client(e.alice).PinEmailCertificate(ctx, connect.NewRequest(&osadminv1.PinEmailCertificateRequest{Settings: s, Sha256: "AB:CD"}))
	symbolIn(t, err, connect.CodeInvalidArgument, "EMAIL_INVALID")
	s.Tls = osadminv1.EmailTls_EMAIL_TLS_NONE
	_, err = e.client(e.alice).PinEmailCertificate(ctx, connect.NewRequest(&osadminv1.PinEmailCertificateRequest{Settings: s, Sha256: pinB}))
	symbolIn(t, err, connect.CodeInvalidArgument, "EMAIL_INVALID")
}

// Replacing a pin needs the old one named again, and the audit entry has
// both.
func TestReplacingAPinNeedsTheOldOne(t *testing.T) {
	presented := pinB
	e := pinBox(t, &presented)
	ctx := context.Background()
	s := relaySettings()
	s.PinSha256 = pinA
	_, err := e.client(e.alice).PinEmailCertificate(ctx, connect.NewRequest(&osadminv1.PinEmailCertificateRequest{Settings: s, Sha256: pinB}))
	symbolIn(t, err, connect.CodeInvalidArgument, "EMAIL_INVALID")
	_, err = e.client(e.alice).PinEmailCertificate(ctx, connect.NewRequest(&osadminv1.PinEmailCertificateRequest{Settings: s, Sha256: pinB, ReplacesSha256: pinB}))
	symbolIn(t, err, connect.CodeInvalidArgument, "EMAIL_INVALID")
	r, err := e.client(e.alice).PinEmailCertificate(ctx, connect.NewRequest(&osadminv1.PinEmailCertificateRequest{Settings: s, Sha256: pinB, ReplacesSha256: strings.ToLower(pinA)}))
	if err != nil || r.Msg.GetSettings().GetPinSha256() != pinB {
		t.Fatalf("%v %v", r, err)
	}
	if a := lastEntry(t, e.log, "product.email.pin"); a.Detail["pinAdded"] != pinB || a.Detail["pinRemoved"] != pinA {
		t.Fatalf("audit %+v", a)
	}
}

// SetEmail saves the pin and audits a pin added or removed; GetEmail reads
// it back, and a bad pin is refused.
func TestThePinIsSavedWithTheSettings(t *testing.T) {
	e := newEmailBox(t, emailYAML)
	ctx := context.Background()
	e.alice.stepUp("alice")
	ec := e.client(e.alice)
	s := relaySettings()
	s.PinSha256 = "not a fingerprint"
	_, err := ec.SetEmail(ctx, connect.NewRequest(&osadminv1.SetEmailRequest{Settings: s}))
	symbolIn(t, err, connect.CodeInvalidArgument, "EMAIL_INVALID")
	s.PinSha256 = pinA
	if _, err := ec.SetEmail(ctx, connect.NewRequest(&osadminv1.SetEmailRequest{Settings: s})); err != nil {
		t.Fatal(err)
	}
	if a := lastEntry(t, e.log, "product.email.set"); a.Outcome != "ok" || a.Detail["pinAdded"] != pinA || a.Detail["pinRemoved"] != "" {
		t.Fatalf("audit %+v", a)
	}
	g, err := ec.GetEmail(ctx, connect.NewRequest(&osadminv1.GetEmailRequest{}))
	if err != nil || g.Msg.GetSettings().GetPinSha256() != pinA || !g.Msg.GetEncrypted() {
		t.Fatalf("%v %v", g, err)
	}
	e.restarted(t)
	s.PinSha256 = ""
	if _, err := ec.SetEmail(ctx, connect.NewRequest(&osadminv1.SetEmailRequest{Settings: s})); err != nil {
		t.Fatal(err)
	}
	if a := lastEntry(t, e.log, "product.email.set"); a.Detail["pinAdded"] != "" || a.Detail["pinRemoved"] != pinA {
		t.Fatalf("audit %+v", a)
	}
}
