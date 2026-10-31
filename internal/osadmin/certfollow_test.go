// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect" // scrub:allow=fqdn -- a Go module path

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

const replaced = "tls.selfsigned.replace"

func (cb *certBox) fingerprint(t *testing.T) string {
	t.Helper()
	info, err := osadmin.ReadCertInfo(cb.adminDir)
	if err != nil {
		t.Fatal(err)
	}
	return info.Fingerprint
}

// moveTo gives the box these management addresses and tells the follower,
// as a netd address event does.
func (cb *certBox) moveTo(addrs ...string) {
	cb.netd.mu.Lock()
	cb.netd.mgmt = addrs
	cb.netd.mu.Unlock()
	cb.srv.FollowCerts(context.Background())
}

func (cb *certBox) replacements(t *testing.T) []osaudit.Entry {
	t.Helper()
	es, err := cb.log.Entries()
	if err != nil {
		t.Fatal(err)
	}
	var out []osaudit.Entry
	for _, e := range es {
		if e.Action == replaced {
			out = append(out, e)
		}
	}
	return out
}

func (cb *certBox) status(t *testing.T, br *browser) *osadminv1.GetStatusResponse {
	t.Helper()
	st, err := osadminv1connect.NewStatusServiceClient(br.hc, cb.ts.URL).GetStatus(context.Background(), connect.NewRequest(&osadminv1.GetStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return st.Msg
}

func changedWarning(st *osadminv1.GetStatusResponse) string {
	for _, w := range st.GetWarnings() {
		if w.GetKind() == osadminv1.WarningKind_WARNING_KIND_TLS_CHANGED {
			return w.GetDetail()
		}
	}
	return ""
}

// A DHCP lease moves at any hour: no SetNetwork, no pending change, nobody
// watching. The certificate follows on its own, and the console and the
// audit log say what happened.
func TestAnUnattendedLeaseChangeIsFollowedAndSaysSo(t *testing.T) {
	cb := newCertBox(t, false, false)
	alice := cb.browser()
	alice.signIn("alice")
	old := cb.fingerprint(t)

	cb.moveTo("192.0.2.20/24")
	if cb.fingerprint(t) != old {
		t.Fatal("replaced before the addresses settled")
	}
	cb.clk.Advance(osadmin.CertSettle - time.Second)
	if cb.fingerprint(t) != old {
		t.Fatal("replaced before the addresses settled")
	}
	cb.clk.Advance(time.Second)
	now := cb.fingerprint(t)
	if now == old || served(t, cb.addr) != now {
		t.Fatalf("still %s, serving %s", now, served(t, cb.addr))
	}

	e := lastEntry(t, cb.log, replaced)
	if e.Actor != "box" || e.Outcome != "ok" || e.Target != "certificate "+boxHost+", 192.0.2.20" || e.Detail["old"] != old || e.Detail["new"] != now || e.Detail["reason"] != "addresses" || e.Detail["endpoints"] != "admin" {
		t.Fatalf("%+v", e)
	}
	st := cb.status(t, alice)
	if st.GetTlsFingerprint() != now {
		t.Fatalf("Status says %s, want %s", st.GetTlsFingerprint(), now)
	}
	c := st.GetTlsChange()
	if c.GetOldFingerprint() != old || c.GetNewFingerprint() != now || c.GetReason() != "addresses" || c.GetRestored() || !c.GetAt().AsTime().Equal(cb.clk.Now()) {
		t.Fatalf("%+v", c)
	}
	if w := changedWarning(st); !strings.Contains(w, "addresses changed") {
		t.Fatalf("warning %q", w)
	}
	// It stays long enough for a weekend, then goes.
	cb.clk.Advance(6 * 24 * time.Hour)
	later := cb.browser()
	later.signIn("alice")
	if changedWarning(cb.status(t, later)) == "" {
		t.Fatal("the note is gone within a week")
	}
	cb.clk.Advance(25 * time.Hour)
	last := cb.browser()
	last.signIn("alice")
	if st := cb.status(t, last); changedWarning(st) != "" || st.GetTlsChange() != nil {
		t.Fatalf("still shown: %+v", st.GetTlsChange())
	}
}

// After a boot the addresses arrive one at a time. One certificate covers
// the set they settle on.
func TestAddressesThatArriveOneAtATimeMakeOneCertificate(t *testing.T) {
	cb := newCertBox(t, false, false)
	cb.moveTo("192.0.2.20/24")
	cb.clk.Advance(10 * time.Second)
	cb.moveTo("192.0.2.20/24", "2001:db8::20/64")
	cb.clk.Advance(osadmin.CertSettle - time.Second)
	if n := len(cb.replacements(t)); n != 0 {
		t.Fatalf("%d replaced before the set settled", n)
	}
	cb.clk.Advance(time.Second)
	if n := len(cb.replacements(t)); n != 1 {
		t.Fatalf("%d certificates, want one", n)
	}
	cb.clk.Advance(time.Hour)
	cb.srv.FollowCerts(context.Background())
	if n := len(cb.replacements(t)); n != 1 {
		t.Fatalf("%d certificates, want one", n)
	}
}

func TestAnAddressThatGoesAwayBeforeItSettlesChangesNothing(t *testing.T) {
	cb := newCertBox(t, false, false)
	old := cb.fingerprint(t)
	cb.moveTo("192.0.2.20/24")
	cb.clk.Advance(5 * time.Second)
	cb.moveTo("192.0.2.10/24")
	cb.clk.Advance(time.Hour)
	if cb.fingerprint(t) != old || len(cb.replacements(t)) != 0 {
		t.Fatal("a flap replaced the certificate")
	}
}

// A change on the Network page that nobody confirms never reaches the
// certificate, so there's nothing to put back.
func TestAChangeThatRevertsLeavesTheCertificateAlone(t *testing.T) {
	cb := newCertBox(t, false, false)
	alice := cb.browser()
	alice.signIn("alice")
	nc := osadminv1connect.NewNetworkServiceClient(alice.hc, cb.ts.URL)
	old := cb.fingerprint(t)
	if _, err := nc.SetNetwork(context.Background(), connect.NewRequest(&osadminv1.SetNetworkRequest{Settings: defaultSettings()})); err != nil {
		t.Fatal(err)
	}
	cb.moveTo("192.0.2.20/24")
	cb.clk.Advance(90 * time.Second)
	if cb.fingerprint(t) != old {
		t.Fatal("replaced while the change waited")
	}
	cb.netd.revert()
	cb.moveTo("192.0.2.10/24")
	cb.clk.Advance(time.Hour)
	if got := cb.fingerprint(t); got != old || served(t, cb.addr) != old || len(cb.replacements(t)) != 0 {
		t.Fatalf("%s, want %s", got, old)
	}
	later := cb.browser()
	later.signIn("alice")
	if changedWarning(cb.status(t, later)) != "" {
		t.Fatal("a note about a change that didn't happen")
	}
}

// A confirmed change is followed without waiting for the window to end,
// once the addresses have settled.
func TestAConfirmedChangeIsFollowed(t *testing.T) {
	cb := newCertBox(t, false, false)
	alice := cb.browser()
	alice.signIn("alice")
	ctx := context.Background()
	nc := osadminv1connect.NewNetworkServiceClient(alice.hc, cb.ts.URL)
	old := cb.fingerprint(t)
	set, err := nc.SetNetwork(ctx, connect.NewRequest(&osadminv1.SetNetworkRequest{Settings: defaultSettings()}))
	if err != nil {
		t.Fatal(err)
	}
	cb.moveTo("192.0.2.20/24")
	cb.clk.Advance(osadmin.CertSettle * 2)
	if cb.fingerprint(t) != old {
		t.Fatal("replaced while the change waited")
	}
	if _, err := nc.ConfirmNetwork(ctx, connect.NewRequest(&osadminv1.ConfirmNetworkRequest{Token: set.Msg.GetToken()})); err != nil {
		t.Fatal(err)
	}
	cb.clk.Advance(osadmin.CertSettle)
	if cb.fingerprint(t) == old {
		t.Fatal("still the old certificate after the confirm")
	}
	if e := lastEntry(t, cb.log, replaced); e.Detail["old"] != old || e.Detail["reason"] != "addresses" {
		t.Fatalf("%+v", e)
	}
}

// A window that ends with no confirm by this path (the K key, a page gone)
// is still looked at once it's over.
func TestTheFollowerLooksAgainWhenTheWindowEnds(t *testing.T) {
	cb := newCertBox(t, false, false)
	old := cb.fingerprint(t)
	cb.netd.mu.Lock()
	cb.netd.pending, cb.netd.changeID = "tok-1", "chg-1"
	cb.netd.mu.Unlock()
	cb.moveTo("192.0.2.20/24")
	cb.netd.mu.Lock()
	cb.netd.pending = ""
	cb.netd.mu.Unlock()
	cb.clk.Advance(2*time.Minute + osadmin.CertSettle)
	if cb.fingerprint(t) == old {
		t.Fatal("not followed after the window")
	}
}

// With no word from netd nobody can say the change is kept, so the
// certificate stays and the follower looks again.
func TestTheCertificateWaitsWhileNetdDoesntAnswer(t *testing.T) {
	cb := newCertBox(t, false, false)
	old := cb.fingerprint(t)
	cb.netd.mu.Lock()
	cb.netd.getDown = true
	cb.netd.mu.Unlock()
	cb.moveTo("192.0.2.20/24")
	cb.clk.Advance(5 * time.Minute)
	if cb.fingerprint(t) != old {
		t.Fatal("replaced without knowing the change is kept")
	}
	cb.netd.mu.Lock()
	cb.netd.getDown = false
	cb.netd.mu.Unlock()
	cb.clk.Advance(5 * time.Minute)
	if cb.fingerprint(t) == old {
		t.Fatal("not followed once netd answered")
	}
}

// netd undoes a change left unconfirmed when the box stopped before it
// answers anyone, so the box comes back on the addresses the certificate
// names, and accessd's look at start finds nothing to do.
func TestAChangeUndoneAtStartKeepsTheCertificate(t *testing.T) {
	cb := newCertBox(t, false, false)
	old := cb.fingerprint(t)
	cb.netd.mu.Lock()
	cb.netd.last = &netdv1.ChangeOutcome{ChangeId: "start-1", Reverted: true, AtStart: true}
	cb.netd.mu.Unlock()
	cb.srv.FollowCerts(context.Background())
	cb.clk.Advance(time.Hour)
	if cb.fingerprint(t) != old || len(cb.replacements(t)) != 0 {
		t.Fatal("the certificate moved")
	}
}

// A lease that goes and comes back for good, past the settling time: the
// fingerprint the admin checked returns, and the audit says it was put back.
func TestTheCheckedFingerprintComesBackWithItsAddress(t *testing.T) {
	cb := newCertBox(t, false, false)
	alice := cb.browser()
	alice.signIn("alice")
	old := cb.fingerprint(t)
	cb.moveTo("192.0.2.20/24")
	cb.clk.Advance(osadmin.CertSettle)
	moved := cb.fingerprint(t)
	cb.moveTo("192.0.2.10/24")
	cb.clk.Advance(osadmin.CertSettle)
	if got := cb.fingerprint(t); got != old {
		t.Fatalf("%s, want %s", got, old)
	}
	if got := served(t, cb.addr); got != old {
		t.Fatalf("serving %s, want %s", got, old)
	}
	e := lastEntry(t, cb.log, replaced)
	if e.Detail["old"] != moved || e.Detail["new"] != old || e.Detail["restored"] != "true" {
		t.Fatalf("%+v", e)
	}
	st := cb.status(t, alice)
	if !st.GetTlsChange().GetRestored() || !strings.Contains(changedWarning(st), "put its earlier certificate back") {
		t.Fatalf("%+v %q", st.GetTlsChange(), changedWarning(st))
	}
}

// Renewal needs no change of address and no settling: the accessd minute
// tick finds it.
func TestACertificateNearItsEndIsRenewedOnALook(t *testing.T) {
	cb := newCertBox(t, false, false)
	info, err := osadmin.ReadCertInfo(cb.adminDir)
	if err != nil {
		t.Fatal(err)
	}
	cb.clk.Advance(info.Expires.Sub(cb.clk.Now()) - 29*24*time.Hour)
	cb.srv.FollowCerts(context.Background())
	if cb.fingerprint(t) == info.Fingerprint {
		t.Fatal("not renewed")
	}
	if e := lastEntry(t, cb.log, replaced); e.Detail["reason"] != "expiring" {
		t.Fatalf("%+v", e)
	}
}

// An owner's certificate is never replaced; the warning that already exists
// says it no longer covers the box.
func TestAnAssignedCertificateIsLeftAloneAndWarns(t *testing.T) {
	cb := newCertBox(t, false, false)
	br := cb.browser()
	br.signIn("alice")
	ctx := context.Background()
	l := cb.leaf(t, "192.0.2.10")
	imp, err := br.tls().ImportCertificate(ctx, connect.NewRequest(&osadminv1.ImportCertificateRequest{CertificatePem: string(l.PEM), ChainPem: cb.chain(), KeyPem: string(l.KeyPEM)}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := br.tls().AssignCertificate(ctx, connect.NewRequest(&osadminv1.AssignCertificateRequest{EndpointId: "admin", CertificateId: imp.Msg.GetCertificate().GetId()})); err != nil {
		t.Fatal(err)
	}
	cb.moveTo("192.0.2.20/24")
	cb.clk.Advance(time.Minute)
	if got := cb.fingerprint(t); got != imp.Msg.GetCertificate().GetFingerprint() || len(cb.replacements(t)) != 0 {
		t.Fatalf("%s replaced it", got)
	}
	found := false
	for _, w := range cb.status(t, br).GetWarnings() {
		found = found || w.GetKind() == osadminv1.WarningKind_WARNING_KIND_TLS_NAMES
	}
	if !found {
		t.Fatal("no names warning")
	}
}
