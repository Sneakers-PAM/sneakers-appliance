// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package certstore_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
)

// ownFixture is a store whose box has hostname and mgmt, serving its own
// self-signed certificate for those, with a clock the test moves.
func ownFixture(t *testing.T, hostname string, mgmt []string) (*fixture, *time.Time) {
	t.Helper()
	f := newFixtureWith(t, hostname, mgmt)
	now := time.Now()
	f.s.SetNow(func() time.Time { return now })
	crt, key, err := certstore.NewSelfSigned(hostname, mgmt, now)
	if err != nil {
		t.Fatal(err)
	}
	f.write("tls.crt", crt)
	f.write("tls.key", key)
	return f, &now
}

func (f *fixture) fingerprint() string {
	f.t.Helper()
	blk, _ := pem.Decode(f.read("tls.crt"))
	if blk == nil {
		f.t.Fatal("no certificate on :8443")
	}
	return certstore.Fingerprint(blk.Bytes)
}

func (f *fixture) leaf() *x509.Certificate {
	f.t.Helper()
	blk, _ := pem.Decode(f.read("tls.crt"))
	if blk == nil {
		f.t.Fatal("no certificate on :8443")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

// follow runs the follower and fails the test on an error.
func (f *fixture) follow() certstore.OwnChange {
	f.t.Helper()
	c, err := f.s.FollowOwn(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

// wantPair checks :8443's files load as a matching pair.
func (f *fixture) wantPair() {
	f.t.Helper()
	if _, err := tls.LoadX509KeyPair(filepath.Join(f.admin, "tls.crt"), filepath.Join(f.admin, "tls.key")); err != nil {
		f.t.Fatal(err)
	}
}

func ipNames(c *x509.Certificate) []string {
	var out []string
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

func TestAnAddressTheCertificateDoesntNameReplacesItAndSaysWhy(t *testing.T) {
	f, _ := ownFixture(t, host, []string{"192.0.2.10"})
	ctx := context.Background()
	old := f.fingerprint()
	f.addrs = []string{"192.0.2.20/24"}
	need, err := f.s.OwnNeed(ctx)
	if err != nil || need.Reason != certstore.OwnAddresses {
		t.Fatalf("need %+v %v", need, err)
	}
	c := f.follow()
	if c.Reason != certstore.OwnAddresses || c.Old != old || c.New != f.fingerprint() || c.New == old || c.Restored {
		t.Fatalf("%+v", c)
	}
	if !slices.Equal(c.Endpoints, []string{certstore.EndpointAdmin}) {
		t.Fatalf("endpoints %v", c.Endpoints)
	}
	if got := ipNames(f.leaf()); !slices.Equal(got, []string{"192.0.2.20"}) {
		t.Fatalf("names %v", got)
	}
	f.wantPair()
	if need, _ := f.s.OwnNeed(ctx); need.Reason != "" {
		t.Fatalf("still needs %+v", need)
	}
	if again := f.follow(); again.New != "" {
		t.Fatalf("a second look changed it: %+v", again)
	}
}

func TestANewHostNameReplacesIt(t *testing.T) {
	f, _ := ownFixture(t, host, []string{"192.0.2.10"})
	f.host = "other.example.org"
	c := f.follow()
	if c.Reason != certstore.OwnHostName || f.leaf().DNSNames[0] != "other.example.org" {
		t.Fatalf("%+v %v", c, f.leaf().DNSNames)
	}
}

// After a reboot the addresses come back one at a time; a certificate that
// names more than the box has now keeps its fingerprint.
func TestACertificateThatNamesMoreThanTheBoxHasIsKept(t *testing.T) {
	f, _ := ownFixture(t, host, []string{"192.0.2.10", "2001:db8::10"})
	old := f.fingerprint()
	f.addrs = []string{"192.0.2.10"}
	if c := f.follow(); c.New != "" || f.fingerprint() != old {
		t.Fatalf("%+v", c)
	}
}

func TestABoxWithNoAddressKeepsItsCertificate(t *testing.T) {
	f, _ := ownFixture(t, host, []string{"192.0.2.10"})
	old := f.fingerprint()
	f.addrs = nil
	if c := f.follow(); c.New != "" || f.fingerprint() != old {
		t.Fatalf("%+v", c)
	}
}

func TestACertificateNearItsEndIsRenewed(t *testing.T) {
	f, now := ownFixture(t, host, []string{"192.0.2.10"})
	ctx := context.Background()
	old := f.leaf()
	*now = old.NotAfter.Add(-certstore.RenewBefore - time.Hour)
	if need, _ := f.s.OwnNeed(ctx); need.Reason != "" {
		t.Fatalf("31 days out, need %+v", need)
	}
	*now = old.NotAfter.Add(-certstore.RenewBefore + time.Hour)
	need, err := f.s.OwnNeed(ctx)
	if err != nil || need.Reason != certstore.OwnExpiring {
		t.Fatalf("need %+v %v", need, err)
	}
	if c := f.follow(); c.Reason != certstore.OwnExpiring || !f.leaf().NotAfter.After(old.NotAfter) {
		t.Fatalf("%+v", c)
	}
}

// A certificate an owner assigned is never replaced: Status warns instead.
func TestAnAssignedCertificateIsNeverReplaced(t *testing.T) {
	f, _ := ownFixture(t, host, []string{"192.0.2.10"})
	ctx := context.Background()
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{"192.0.2.10"}})
	c, _, err := f.s.Import(ctx, certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: f.chain(), KeyPEM: string(l.KeyPEM)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Assign(ctx, certstore.EndpointAdmin, c.ID); err != nil {
		t.Fatal(err)
	}
	f.host, f.addrs = "", []string{"192.0.2.20"}
	if need, _ := f.s.OwnNeed(ctx); need.Reason != "" {
		t.Fatalf("need %+v", need)
	}
	if ch := f.follow(); ch.New != "" {
		t.Fatalf("%+v", ch)
	}
	if !bytes.HasPrefix(f.read("tls.crt"), l.PEM) {
		t.Fatal("the assigned certificate was replaced")
	}
	snap, err := f.s.Snapshot(ctx)
	if err != nil || endpoint(snap, certstore.EndpointAdmin).State != certstore.StateNames {
		t.Fatalf("%+v %v", endpoint(snap, certstore.EndpointAdmin), err)
	}
}

// A lease that moves and moves back ends on the certificate the admin
// checked, with its own key.
func TestTheOldCertificateComesBackWhenTheAddressDoes(t *testing.T) {
	f, _ := ownFixture(t, host, []string{"192.0.2.10"})
	first := f.fingerprint()
	f.addrs = []string{"192.0.2.20"}
	moved := f.follow()
	f.addrs = []string{"192.0.2.10"}
	back := f.follow()
	if !back.Restored || back.New != first || back.Old != moved.New || back.Reason != certstore.OwnAddresses {
		t.Fatalf("%+v", back)
	}
	if f.fingerprint() != first {
		t.Fatal("the certificate the box had isn't back")
	}
	f.wantPair()
	// And again: the one in between is kept the same way.
	f.addrs = []string{"192.0.2.20"}
	if again := f.follow(); !again.Restored || again.New != moved.New {
		t.Fatalf("%+v", again)
	}
	f.wantPair()
}

func TestAPreviousCertificateNearItsEndDoesntComeBack(t *testing.T) {
	f, now := ownFixture(t, host, []string{"192.0.2.10"})
	first := f.fingerprint()
	*now = f.leaf().NotAfter.Add(-certstore.RenewBefore - time.Hour)
	f.addrs = []string{"192.0.2.20"}
	f.follow()
	*now = now.Add(2 * time.Hour)
	f.addrs = []string{"192.0.2.10"}
	if c := f.follow(); c.Restored || c.New == first {
		t.Fatalf("%+v", c)
	}
}

// Replacing the certificate gives up the old fingerprint for good unless
// its key is kept, so a sealed store that doesn't answer holds it back.
func TestTheCertificateStaysWhenTheOldOneCantBeKept(t *testing.T) {
	f, _ := ownFixture(t, host, []string{"192.0.2.10"})
	old := f.fingerprint()
	f.addrs = []string{"192.0.2.20"}
	f.sealer.err = errors.New("key custody doesn't answer")
	if _, err := f.s.FollowOwn(context.Background()); err == nil {
		t.Fatal("no error")
	}
	if f.fingerprint() != old {
		t.Fatal("the certificate moved")
	}
	f.sealer.err = nil
	if c := f.follow(); c.Old != old || c.New == old {
		t.Fatalf("%+v", c)
	}
}

func TestTheLastChangeSurvivesAReopen(t *testing.T) {
	f, _ := ownFixture(t, host, []string{"192.0.2.10"})
	if _, ok := f.s.LastOwnChange(); ok {
		t.Fatal("a change before any")
	}
	f.addrs = []string{"192.0.2.20"}
	c := f.follow()
	got, ok := reopen(t, f, nil).LastOwnChange()
	if !ok || got.New != c.New || got.Old != c.Old || got.Reason != c.Reason || !got.At.Equal(c.At) {
		t.Fatalf("%+v", got)
	}
}

// Assigning and reverting doesn't change the fingerprint either while the
// box's own certificate still names the box.
func TestRevertKeepsACertificateThatNamesMoreThanTheBoxHas(t *testing.T) {
	f, _ := ownFixture(t, host, []string{"192.0.2.10", "2001:db8::10"})
	ctx := context.Background()
	selfCrt := f.read("tls.crt")
	l := f.ca.Issue(t, testpki.LeafOptions{Names: []string{host}})
	c, _, err := f.s.Import(ctx, certstore.ImportRequest{CertificatePEM: string(l.PEM), ChainPEM: f.chain(), KeyPEM: string(l.KeyPEM)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Assign(ctx, certstore.EndpointAdmin, c.ID); err != nil {
		t.Fatal(err)
	}
	f.addrs = []string{"192.0.2.10"}
	if _, err := f.s.Revert(ctx, certstore.EndpointAdmin); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.read("tls.crt"), selfCrt) {
		t.Fatal("a new certificate instead of the box's own")
	}
}

// 443 serves a copy of the box's own certificate, so a replaced one reaches
// the edge as well, in the same change.
func TestTheEdgeFollowsTheBoxsOwnCertificate(t *testing.T) {
	e := &fakeEdge{installed: true}
	f, _ := ownFixture(t, host, []string{"192.0.2.10"})
	f.s.SetProduct(e, nil)
	e.crt, e.key = f.read("tls.crt"), f.read("tls.key")
	f.addrs = []string{"192.0.2.20"}
	c := f.follow()
	if !slices.Equal(c.Endpoints, []string{certstore.EndpointAdmin, certstore.EndpointProduct}) {
		t.Fatalf("endpoints %v", c.Endpoints)
	}
	if !bytes.Equal(e.crt, f.read("tls.crt")) || !bytes.Equal(e.key, f.read("tls.key")) {
		t.Fatal("the edge still has the old certificate")
	}
}

// A certificate an owner assigned to 443 stays, whatever :8443 does.
func TestAnEdgeWithAnAssignedCertificateIsLeftAlone(t *testing.T) {
	e := &fakeEdge{installed: true, assigned: true, crt: []byte("assigned"), key: []byte("assigned-key")}
	f, _ := ownFixture(t, host, []string{"192.0.2.10"})
	f.s.SetProduct(e, nil)
	f.addrs = []string{"192.0.2.20"}
	if c := f.follow(); !slices.Equal(c.Endpoints, []string{certstore.EndpointAdmin}) {
		t.Fatalf("endpoints %v", c.Endpoints)
	}
	if string(e.crt) != "assigned" {
		t.Fatal("the assigned certificate was replaced")
	}
}

func TestAnEdgeWithNoProductIsLeftAlone(t *testing.T) {
	e := &fakeEdge{}
	f, _ := ownFixture(t, host, []string{"192.0.2.10"})
	f.s.SetProduct(e, nil)
	f.addrs = []string{"192.0.2.20"}
	if c := f.follow(); !slices.Equal(c.Endpoints, []string{certstore.EndpointAdmin}) || e.crt != nil {
		t.Fatalf("%+v %q", c, e.crt)
	}
}

// A box that renewed :8443 before the edge followed, or whose write failed,
// catches up on the next look, and that is audited too.
func TestAnEdgeThatFellBehindCatchesUp(t *testing.T) {
	e := &fakeEdge{installed: true, crt: []byte("older")}
	f, _ := ownFixture(t, host, []string{"192.0.2.10"})
	f.s.SetProduct(e, nil)
	blk := f.fingerprint()
	c := f.follow()
	if c.Reason != certstore.OwnEdgeBehind || c.New != blk || !slices.Equal(c.Endpoints, []string{certstore.EndpointProduct}) {
		t.Fatalf("%+v", c)
	}
	if again := f.follow(); again.New != "" {
		t.Fatalf("%+v", again)
	}
}

func TestAFailedEdgeWriteIsRetried(t *testing.T) {
	e := &fakeEdge{installed: true}
	f, _ := ownFixture(t, host, []string{"192.0.2.10"})
	f.s.SetProduct(e, nil)
	e.crt, e.key = f.read("tls.crt"), f.read("tls.key")
	e.followErr = errors.New("the manifests directory is full")
	f.addrs = []string{"192.0.2.20"}
	c, err := f.s.FollowOwn(context.Background())
	if err == nil || c.New == "" {
		t.Fatalf("the change is reported along with the error: %+v %v", c, err)
	}
	e.followErr = nil
	if c := f.follow(); !slices.Equal(c.Endpoints, []string{certstore.EndpointProduct}) || !bytes.Equal(e.crt, f.read("tls.crt")) {
		t.Fatalf("%+v", c)
	}
}

// edgefall holds its own copy for 443 while k0s is down.
func TestTheFallbackIsHandedTheNewCertificate(t *testing.T) {
	f, _ := ownFixture(t, host, []string{"192.0.2.10"})
	fails, calls := 1, 0
	f.s.SetFallback(func() error {
		calls++
		if fails > 0 {
			fails--
			return errors.New("not yet")
		}
		return nil
	})
	f.follow()
	if calls != 0 {
		t.Fatalf("called %d times with nothing changed", calls)
	}
	f.addrs = []string{"192.0.2.20"}
	if _, err := f.s.FollowOwn(context.Background()); err == nil || calls != 1 {
		t.Fatalf("%v, %d calls", err, calls)
	}
	f.follow()
	f.follow()
	if calls != 2 {
		t.Fatalf("%d calls: retried until it took, then left alone", calls)
	}
}
