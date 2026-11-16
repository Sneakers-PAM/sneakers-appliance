// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
)

// cmBox is cert-manager as the box drives it.
type cmBox struct {
	mu      sync.Mutex
	applied []string
	status  certstore.ACMEStatus
}

func (c *cmBox) Available() (bool, string) { return true, "" }
func (c *cmBox) Apply(_ context.Context, m []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.applied = append(c.applied, string(m))
	return nil
}
func (c *cmBox) Remove(context.Context) error { return nil }
func (c *cmBox) Status(context.Context) (certstore.ACMEStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status, nil
}

func withACME(c *cmBox) func(*certstore.Options) {
	return func(o *certstore.Options) { o.ACME = c }
}

func TestSetAcmeWritesTheStackAndAuditsWithoutTheToken(t *testing.T) {
	cm := &cmBox{}
	cb := newCertBox(t, false, false, withACME(cm))
	br := cb.browser()
	br.signIn("alice")
	ctx := context.Background()
	_, err := br.tls().SetAcme(ctx, connect.NewRequest(&osadminv1.SetAcmeRequest{
		Issuer: osadminv1.AcmeIssuer_ACME_ISSUER_LETSENCRYPT_STAGING, Email: "ops@example.org",
		Challenge: osadminv1.AcmeChallenge_ACME_CHALLENGE_DNS01, DnsProvider: "cloudflare", DnsToken: "tok-secret-1",
		EndpointIds: []string{"admin"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cm.applied) != 1 || !strings.Contains(cm.applied[0], "acme-staging-v02") || !strings.Contains(cm.applied[0], boxHost) {
		t.Fatalf("stack: %v", cm.applied)
	}
	e := lastEntry(t, cb.log, "tls.acme.set")
	if e.Outcome != "ok" || e.Detail["issuer"] != "letsencrypt-staging" || e.Detail["challenge"] != "dns-01" || e.Detail["endpoints"] != "admin" {
		t.Fatalf("%+v", e)
	}
	for k, v := range e.Detail {
		if strings.Contains(v, "tok-secret-1") || strings.Contains(k, "token") {
			t.Fatalf("the audit entry carries the token: %s=%s", k, v)
		}
	}
	st, err := br.tls().GetCertificateStore(ctx, connect.NewRequest(&osadminv1.GetCertificateStoreRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Msg.GetAcme().GetAvailable() || st.Msg.GetEndpoints()[0].GetSource() != osadminv1.EndpointSource_ENDPOINT_SOURCE_ACME {
		t.Fatalf("%+v", st.Msg)
	}
}

func TestSetAcmeRefusesWhatIsntAnIssuer(t *testing.T) {
	cb := newCertBox(t, false, false, withACME(&cmBox{}))
	br := cb.browser()
	br.signIn("alice")
	_, err := br.tls().SetAcme(context.Background(), connect.NewRequest(&osadminv1.SetAcmeRequest{Email: "ops@example.org", EndpointIds: []string{"admin"}}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "TLS_INVALID")
}

func TestTheFollowerAppliesWhatCertManagerIssuedAndAuditsIt(t *testing.T) {
	cm := &cmBox{}
	cb := newCertBox(t, false, false, withACME(cm))
	br := cb.browser()
	br.signIn("alice")
	ctx := context.Background()
	_, err := br.tls().SetAcme(ctx, connect.NewRequest(&osadminv1.SetAcmeRequest{
		Issuer: osadminv1.AcmeIssuer_ACME_ISSUER_LETSENCRYPT_STAGING, Email: "ops@example.org",
		Challenge: osadminv1.AcmeChallenge_ACME_CHALLENGE_HTTP01, EndpointIds: []string{"admin"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	before := served(t, cb.addr)
	l := cb.leaf(t, boxHost)
	cm.mu.Lock()
	cm.status = certstore.ACMEStatus{Ready: true, CertPEM: l.PEM, KeyPEM: l.KeyPEM}
	cm.mu.Unlock()
	cb.srv.FollowACME(ctx)
	if got := served(t, cb.addr); got == before || got != certstore.Fingerprint(l.Cert.Raw) {
		t.Fatalf(":8443 serves %s, want the issued certificate (was %s)", got, before)
	}
	e := lastEntry(t, cb.log, "tls.acme.issue")
	if e.Actor != "box" || e.Outcome != "ok" || e.Detail["endpoint"] != "admin" || e.Detail["fingerprint"] == "" {
		t.Fatalf("%+v", e)
	}
	// A failure is audited once.
	cm.mu.Lock()
	cm.status.Failure = "the CA refused the challenge"
	cm.mu.Unlock()
	cb.srv.FollowACME(ctx)
	cb.srv.FollowACME(ctx)
	f := lastEntry(t, cb.log, "tls.acme.fail")
	if f.Outcome != "refused" || f.Code != "TLS_ACME_FAILED" || f.Detail["reason"] != "the CA refused the challenge" {
		t.Fatalf("%+v", f)
	}
	var n int
	es, _ := cb.log.Entries()
	for _, x := range es {
		if x.Action == "tls.acme.fail" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d failure entries for one problem", n)
	}
	// The renewal Now asks for goes into the stack.
	if _, err := br.tls().RenewNow(ctx, connect.NewRequest(&osadminv1.RenewNowRequest{EndpointId: "admin"})); err != nil {
		t.Fatal(err)
	}
	if last := cm.applied[len(cm.applied)-1]; !strings.Contains(last, "renewal-1") {
		t.Fatalf("stack: %s", last)
	}
}
