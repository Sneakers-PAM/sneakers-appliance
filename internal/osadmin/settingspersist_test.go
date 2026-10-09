// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

// The update mirror, the update window and the access policy are kept on
// the state volume: a new osadmin on the same volume (a reboot, a base
// update or a revert) reads back what the admin set.
func TestTheUpdateAndAccessPoliciesSurviveARestart(t *testing.T) {
	var opts osadmin.Options
	b := newBox(t, false, func(_ *box, o *osadmin.Options) { opts = *o })
	ctx := context.Background()
	alice := b.browser()
	alice.signIn("alice")
	alice.stepUp("alice")
	pol := &osadminv1.UpgradePolicy{Mode: "manual", WindowStart: "03:30", WindowMinutes: 90, MirrorUrl: "https://mirror.sneakers.example.org/updates"}
	if _, err := alice.upgrade().SetUpgradePolicy(ctx, connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol})); err != nil {
		t.Fatal(err)
	}
	ac := alice.access()
	got, err := ac.ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	ap := got.Msg.GetAccessPolicy()
	ap.RootSessionMinutes, ap.SshKeyValidDays = 25, 90
	if _, err := ac.SetAccessPolicy(ctx, connect.NewRequest(&osadminv1.SetAccessPolicyRequest{Policy: ap})); err != nil {
		t.Fatal(err)
	}

	for _, when := range []string{"a reboot", "a base update", "a revert"} {
		b.srv.Close()
		b.ts.Close()
		b.srv = osadmin.New(opts)
		b.ts = httptest.NewTLSServer(b.srv.Handler())
		t.Cleanup(b.ts.Close)
		t.Cleanup(b.srv.Close)
		br := b.browser()
		br.signIn("alice")
		u, err := br.upgrade().GetUpgrades(ctx, connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		if p := u.Msg.GetPolicy(); p.GetMode() != "manual" || p.GetWindowStart() != "03:30" || p.GetWindowMinutes() != 90 || p.GetMirrorUrl() != pol.GetMirrorUrl() {
			t.Fatalf("after %s the update policy is %v", when, p)
		}
		a, err := osadminv1connect.NewAccessServiceClient(br.hc, b.ts.URL).ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		if p := a.Msg.GetAccessPolicy(); p.GetRootSessionMinutes() != 25 || p.GetSshKeyValidDays() != 90 {
			t.Fatalf("after %s the access policy is %v", when, p)
		}
	}
}
