// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
)

// A box reads the newest releases' indexes, not only the newest one's: an
// earlier release's product that fits the box is offered too, each from the
// release it was published in.
func TestUpdateCheckOffersTheEarlierReleasesToo(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	g.release("v0.2.0", false, false)
	g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	builtin(t, alice, nil)

	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.2.0,0.1.1" {
		t.Fatalf("both releases' products: %v %v", c, err)
	}
	// The file an offer names is fetched from its own release.
	if _, err := alice.upgrade().FetchUpdate(context.Background(), connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "sneakers-product-0.1.1-amd64.bin"})); err != nil {
		t.Fatalf("fetch the earlier release's product: %v", err)
	}
	if got := g.asked("v0.1.1"); !slices.Contains(got, "v0.1.1/sneakers-product-0.1.1-amd64.bin") {
		t.Fatalf("the earlier product wasn't fetched from its release: %v", g.gets)
	}
	for _, f := range g.asked("v0.2.0") {
		if strings.Contains(f, "product-0.1.1") {
			t.Fatalf("the earlier product was asked of the newer release: %s", f)
		}
	}
}

// The history is bounded: with a history of one, only the newest release is
// read, as before.
func TestAHistoryOfOneReadsOnlyTheNewestRelease(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g, func(_ *box, o *osadmin.Options) { o.Upgrade.ReleaseHistory = 1 })
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	g.release("v0.2.0", false, false)
	g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	builtin(t, alice, nil)
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.2.0" {
		t.Fatalf("a history of one: %v %v", c, err)
	}
	if len(g.asked("v0.1.1")) != 0 {
		t.Fatalf("the earlier release was read: %v", g.asked("v0.1.1"))
	}
}

// An earlier release that doesn't verify is skipped by itself, with a note;
// the newest and the other releases still offer what they have.
func TestAnEarlierReleaseThatDoesntVerifyIsSkippedAlone(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.0", false, false)
	g.publish(t, "v0.1.0", b.sign, productBin(t, b.sign, b.enc, "0.1.0", "0.0.9"))
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", testpki.ECDSA(t), productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	g.release("v0.2.0", false, false)
	g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	builtin(t, alice, nil)
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.2.0" {
		t.Fatalf("the newest release's product: %v %v", c, err)
	}
	if !strings.Contains(c.GetPublishingNote(), "v0.1.1's index doesn't verify") {
		t.Fatalf("the skipped earlier release isn't named: %q", c.GetPublishingNote())
	}
}

// An earlier release still being published is skipped by itself too.
func TestAnEarlierReleaseStillBeingPublishedIsSkippedAlone(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	g.remove("v0.1.1", "sneakers-product-0.1.1-amd64.bin")
	g.release("v0.2.0", false, false)
	g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	builtin(t, alice, nil)
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.2.0" {
		t.Fatalf("the newest release's product: %v %v", c, err)
	}
	if !strings.Contains(c.GetPublishingNote(), "v0.1.1 is being published") {
		t.Fatalf("the earlier release's note: %q", c.GetPublishingNote())
	}
}

// A product that doesn't fit the running base is not offered, from any
// release, however many are read.
func TestAProductForAnotherBaseIsNotOfferedFromAnEarlierRelease(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "9.9.9"))
	g.release("v0.2.0", false, false)
	g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	builtin(t, alice, nil)
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.2.0" {
		t.Fatalf("only the product that fits: %v %v", c, err)
	}
}

// The same version in two releases is offered once, from the newer release.
func TestTheSameVersionInTwoReleasesComesFromTheNewerOne(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	g.release("v0.2.0", false, false)
	g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"), productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	builtin(t, alice, nil)
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.2.0,0.1.1" {
		t.Fatalf("each version once: %v %v", c, err)
	}
	if _, err := alice.upgrade().FetchUpdate(context.Background(), connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "sneakers-product-0.1.1-amd64.bin"})); err != nil {
		t.Fatal(err)
	}
	if got := g.asked("v0.1.1"); slices.Contains(got, "v0.1.1/sneakers-product-0.1.1-amd64.bin") {
		t.Fatalf("the version was fetched from the older release: %v", g.gets)
	}
}

// Each offer names the release it comes from.
func TestEachOfferNamesItsRelease(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	g.release("v0.2.0", false, false)
	g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	builtin(t, alice, nil)
	c, err := checkNow(alice)
	if err != nil || len(c.GetProduct()) != 2 {
		t.Fatalf("%v %v", c, err)
	}
	if c.GetProduct()[0].GetReleaseTag() != "v0.2.0" || c.GetProduct()[1].GetReleaseTag() != "v0.1.1" {
		t.Fatalf("release tags: %q, %q", c.GetProduct()[0].GetReleaseTag(), c.GetProduct()[1].GetReleaseTag())
	}
}

// A product newer than the installed one that needs another Base OS isn't
// offered, and the page says which Base OS it needs first.
func TestAProductNeedingAnotherBaseNamesTheBaseItNeeds(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "9.9.9"))
	g.release("v0.2.0", false, false)
	g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	builtin(t, alice, nil)
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.2.0" {
		t.Fatalf("%v %v", c, err)
	}
	u := c.GetUnfitProduct()
	if len(u) != 1 || u[0].GetVersion() != "0.1.1" || u[0].GetReleaseTag() != "v0.1.1" || !strings.Contains(u[0].GetNeeds(), "9.9.9") {
		t.Fatalf("the product that needs another Base OS: %v", u)
	}
}
