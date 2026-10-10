// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxvalues"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netdapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// withBoxValues gives the box its values from the fake netd.
func withBoxValues(b *box, o *osadmin.Options) {
	o.BoxValues = &boxvalues.Box{
		Dir: filepath.Join(b.state, "platform"),
		Names: func(ctx context.Context) (string, []string, error) {
			st, err := o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
			if err != nil {
				return "", nil, err
			}
			var addrs []string
			for _, a := range netdapi.Bindable(st.Msg.GetManagementAddresses()) {
				addrs = append(addrs, a.String())
			}
			return st.Msg.GetHostname(), addrs, nil
		},
		Own: func() string { return "sneakers-0a1b2c3d" },
	}
}

func (b *box) recordedFQDN() string {
	return boxvalues.Read(filepath.Join(b.state, "platform"))[productspec.BoxFQDN]
}

// declareBoxValues makes the installed slot's bundle read box.fqdn, as the
// Sneakers bundle's product.yaml declares.
func (b *box) declareBoxValues() {
	b.t.Helper()
	cur := filepath.Join(b.state, "product", "current")
	if err := os.WriteFile(filepath.Join(cur, productspec.BoxValuesFile), []byte("sneakers.box.invalid box.fqdn\n"), 0o644); err != nil { // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
		b.t.Fatal(err)
	}
}

func (b *box) setHostname(name string, pending bool) {
	b.netd.mu.Lock()
	defer b.netd.mu.Unlock()
	b.netd.hostname = name
	b.netd.pending, b.netd.changeID = "", ""
	if pending {
		b.netd.pending, b.netd.changeID = "tok-1", "chg-1"
	}
}

// A product apply records the box's FQDN the stacks are put in place
// with.
func TestAProductApplyRecordsTheBoxsFQDN(t *testing.T) {
	b := newBox(t, false, withBoxValues)
	alice := b.browser()
	alice.signIn("alice")
	alice.installProduct(t, "0.2.0")
	if got := b.recordedFQDN(); got != "box1.sneakers.example.org" {
		t.Fatalf("recorded %q", got)
	}
}

// A product apply records the box's Base OS and Base Web versions too.
func TestAProductApplyRecordsTheBoxsVersions(t *testing.T) {
	b := newBox(t, false, withBoxValues, func(_ *box, o *osadmin.Options) {
		o.BoxValues.(*boxvalues.Box).Versions = func() (string, string) { return "0.1.0-m", "0.1.0-m2" }
	})
	alice := b.browser()
	alice.signIn("alice")
	alice.installProduct(t, "0.2.0")
	got := boxvalues.Read(filepath.Join(b.state, "platform"))
	if got[productspec.BoxOSVersion] != "0.1.0-m" || got[productspec.BoxWebVersion] != "0.1.0-m2" || got[productspec.BoxFQDN] != "box1.sneakers.example.org" {
		t.Fatalf("recorded %v", got)
	}
}

// A host name change re-applies the product with the new FQDN, but only
// once the change is kept: while it waits for its confirm (120 s) the
// product stays as it is, and it follows when the window is over.
func TestAHostNameChangeReappliesTheProductOnceItIsKept(t *testing.T) {
	b := newBox(t, false, withBoxValues)
	alice := b.browser()
	alice.signIn("alice")
	alice.installProduct(t, "0.2.0")
	b.declareBoxValues()
	ctx := context.Background()
	before := len(b.services.log())

	b.setHostname("box2.sneakers.example.org", true)
	b.srv.HostNameChanged(ctx)
	if got := b.services.log(); len(got) != before || b.recordedFQDN() != "box1.sneakers.example.org" {
		t.Fatalf("an unconfirmed host name reached the product: %v, recorded %q", got, b.recordedFQDN())
	}

	// The change is confirmed; the follower looks again when the window
	// it saw is over.
	b.setHostname("box2.sneakers.example.org", false)
	b.clk.Advance(96 * time.Second)
	if got := b.services.log()[before:]; !slices.Equal(got, []string{"stop k0s", "start k0s"}) {
		t.Fatalf("services %v", got)
	}
	if got := b.recordedFQDN(); got != "box2.sneakers.example.org" {
		t.Fatalf("recorded %q", got)
	}
	g, err := alice.upgrade().GetUpgrades(ctx, connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if h := g.Msg.GetHistory()[0]; h.GetAction() != "apply" || h.GetTarget() != product || h.GetVersion() != "0.2.0" || h.GetOutcome() != "ok" || h.GetDetail() != "host name box2.sneakers.example.org" {
		t.Fatalf("history %v", h)
	}
	if e := lastEntry(t, b.log, "upgrade.apply"); e.Outcome != "ok" || e.Target != "product" || e.Detail["hostname"] != "box2.sneakers.example.org" {
		t.Fatalf("%+v", e)
	}

	// Nothing new: nothing happens.
	n := len(b.services.log())
	b.srv.HostNameChanged(ctx)
	if len(b.services.log()) != n {
		t.Fatal("the product restarted with the same FQDN")
	}
}

// A product whose bundle reads no box values isn't restarted for a new
// host name; the name is only recorded for its next apply.
func TestAHostNameChangeLeavesAProductThatReadsNoBoxValues(t *testing.T) {
	b := newBox(t, false, withBoxValues)
	alice := b.browser()
	alice.signIn("alice")
	alice.installProduct(t, "0.2.0")
	before := len(b.services.log())
	b.setHostname("box2.sneakers.example.org", false)
	b.srv.HostNameChanged(context.Background())
	if len(b.services.log()) != before || b.recordedFQDN() != "box2.sneakers.example.org" {
		t.Fatalf("services %v recorded %q", b.services.log(), b.recordedFQDN())
	}
}

// A box whose product came before box values has none recorded: the
// follower records the FQDN at accessd's start for the next k0s start,
// rather than restarting the product.
func TestTheFirstLookOnlyRecordsTheFQDN(t *testing.T) {
	b := newBox(t, false, withBoxValues)
	alice := b.browser()
	alice.signIn("alice")
	alice.installProduct(t, "0.2.0")
	b.declareBoxValues()
	if err := os.Remove(filepath.Join(b.state, "platform", boxvalues.File)); err != nil {
		t.Fatal(err)
	}
	before := len(b.services.log())
	b.srv.HostNameChanged(context.Background())
	if len(b.services.log()) != before || b.recordedFQDN() != "box1.sneakers.example.org" {
		t.Fatalf("services %v recorded %q", b.services.log(), b.recordedFQDN())
	}
}
