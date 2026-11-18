// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// markWithdrawn replaces tag's index with the same one carrying the withdrawn
// list, signed again.
func markWithdrawn(t *testing.T, g *fakeGitHub, tag string, sign testpki.ECKey, w ...updatepkg.Withdrawn) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	var idx updatepkg.Index
	if err := json.Unmarshal(g.assets[tag+"/"+updatepkg.IndexName], &idx); err != nil {
		t.Fatal(err)
	}
	idx.Withdrawn = w
	b, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	g.assets[tag+"/"+updatepkg.IndexName] = b
	g.assets[tag+"/"+updatepkg.IndexName+".sigstore.json"] = sign.BlobBundle(t, b)
}

func releases(t *testing.T) (*fakeGitHub, *box, *browser) {
	t.Helper()
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	g.release("v0.2.0", false, false)
	g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	builtin(t, alice, nil)
	return g, b, alice
}

// A release the newest index withdraws is not offered, never preferred, and
// listed apart with why, what to use and the release it is in.
func TestAWithdrawnProductIsNotOffered(t *testing.T) {
	g, b, alice := releases(t)
	markWithdrawn(t, g, "v0.2.0", b.sign, updatepkg.Withdrawn{Kind: "product", Version: "0.1.1", Reason: "an update from 0.1.0 fails", Use: "0.2.0"})
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.2.0" || !c.GetProduct()[0].GetPreferred() {
		t.Fatalf("the offers: %v %v", c, err)
	}
	w := c.GetWithdrawn()
	if len(w) != 1 || w[0].GetVersion() != "0.1.1" || w[0].GetReason() != "an update from 0.1.0 fails" || w[0].GetUse() != "0.2.0" || w[0].GetReleaseTag() != "v0.1.1" || w[0].GetTarget() != osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT {
		t.Fatalf("the withdrawn list: %v", w)
	}
}

// The newest release can be withdrawn too: the preferred line moves to the
// newest one that isn't.
func TestTheNewestReleaseCanBeWithdrawn(t *testing.T) {
	g, b, alice := releases(t)
	markWithdrawn(t, g, "v0.2.0", b.sign, updatepkg.Withdrawn{Kind: "product", Version: "0.2.0", Reason: "it is broken", Use: "0.1.1"})
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.1.1" || !c.GetProduct()[0].GetPreferred() || len(c.GetWithdrawn()) != 1 {
		t.Fatalf("the offers: %v %v", c, err)
	}
}

// A marker naming a version no index lists changes nothing.
func TestAMarkerForAnUnlistedVersionIsIgnored(t *testing.T) {
	g, b, alice := releases(t)
	markWithdrawn(t, g, "v0.2.0", b.sign, updatepkg.Withdrawn{Kind: "product", Version: "9.9.9", Reason: "r"})
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.2.0,0.1.1" || len(c.GetWithdrawn()) != 0 {
		t.Fatalf("the offers: %v %v", c, err)
	}
}

// Picking a withdrawn file is refused with the reason; the owner's own upload
// is not.
func TestAWithdrawnFileIsRefusedWithItsReason(t *testing.T) {
	g, b, alice := releases(t)
	markWithdrawn(t, g, "v0.2.0", b.sign, updatepkg.Withdrawn{Kind: "product", Version: "0.1.1", Reason: "an update from 0.1.0 fails", Use: "0.2.0"})
	if _, err := checkNow(alice); err != nil {
		t.Fatal(err)
	}
	_, err := alice.upgrade().FetchUpdate(context.Background(), connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "sneakers-product-0.1.1-amd64.bin"}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_WITHDRAWN")
	if err == nil || !strings.Contains(err.Error(), "an update from 0.1.0 fails") || !strings.Contains(err.Error(), "0.2.0") {
		t.Fatalf("the refusal doesn't say why and what to use: %v", err)
	}
	for _, f := range g.asked("v0.1.1") {
		if strings.HasSuffix(f, ".bin") {
			t.Fatalf("the withdrawn file was fetched: %s", f)
		}
	}
	// The one that isn't withdrawn still comes.
	if _, err := alice.upgrade().FetchUpdate(context.Background(), connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "sneakers-product-0.2.0-amd64.bin"})); err != nil {
		t.Fatalf("the offered file: %v", err)
	}
}
