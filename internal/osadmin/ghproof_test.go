// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build ghproof

package osadmin_test

import (
	"context"
	"net/http"
	"os"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
)

// TestGitHubSourceAgainstARealRepository runs the GitHub source against
// a real test repository on github.com, unauthenticated, as a lab box
// does with the repository override (docs/upgrades.md#testing-the-github-source):
//
//	GHPROOF_REPO=<owner>/<name> GHPROOF_KEY=<lab cosign.pub> GHPROOF_RUNNING=<the base the box runs> \
//	GHPROOF_RC=<the rc tag to pick> GHPROOF_STABLE=<the stable tag to pick> \
//	  go test -tags ghproof -run TestGitHubSourceAgainstARealRepository -v ./internal/osadmin/
func TestGitHubSourceAgainstARealRepository(t *testing.T) {
	repo, keyFile, running := os.Getenv("GHPROOF_REPO"), os.Getenv("GHPROOF_KEY"), os.Getenv("GHPROOF_RUNNING")
	if repo == "" || keyFile == "" || running == "" {
		t.Skip("GHPROOF_REPO, GHPROOF_KEY and GHPROOF_RUNNING name the test repository")
	}
	key, err := os.ReadFile(keyFile) // #nosec G304 -- the test's own input
	if err != nil {
		t.Fatal(err)
	}
	b := newBox(t, false, func(_ *box, o *osadmin.Options) {
		o.Upgrade.Channel, o.Upgrade.ReleaseKeyPEM = release.ChannelLab, key
		o.Upgrade.HTTPClient, o.Upgrade.SystemRoots, o.Upgrade.DirectURL = nil, nil, ""
		o.Upgrade.BuildVersion = running
	})
	b.init.mu.Lock()
	b.init.running = running
	b.init.mu.Unlock()
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	if err := setPolicy(t, alice, &osadminv1.UpgradePolicy{Source: osadmin.SourceBuiltIn, ReleaseRepo: proto.String(repo)}); err != nil {
		t.Fatal(err)
	}

	c, err := checkNow(alice)
	if err != nil {
		t.Fatal(err)
	}
	st := mirrorStatus(t, alice)
	t.Logf("rc channel (default %v): picked %s from %s, builtin %v", st.GetReleaseChannelDefault(), st.GetReleaseTag(), st.GetReleaseRepo(), st.GetBuiltinUrls())
	if want := os.Getenv("GHPROOF_RC"); st.GetReleaseChannel() != "rc" || st.GetReleaseTag() != want {
		t.Fatalf("the rc channel picked %q, want %q", st.GetReleaseTag(), want)
	}
	var patch *osadminv1.UnitOffer
	for _, o := range c.GetBaseOs() {
		t.Logf("Base OS offer: %s %s %s (%d bytes, preferred %v)", o.GetKind(), o.GetVersion(), o.GetFileName(), o.GetSize(), o.GetPreferred())
		if o.GetKind() == "patch" && o.GetPreferred() {
			patch = o
		}
	}
	for _, o := range c.GetBaseWeb() {
		t.Logf("Base Web offer: %s %s", o.GetVersion(), o.GetFileName())
	}
	if patch == nil {
		t.Fatal("no preferred Base OS patch offered")
	}

	// GitHub answers the download with a redirect to its asset host.
	nofollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := nofollow.Get("https://github.com/" + repo + "/releases/download/" + st.GetReleaseTag() + "/" + patch.GetFileName())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, _ := resp.Location()
	if loc != nil {
		t.Logf("the download redirects (%s) to %s", resp.Status, loc.Host)
	}

	f, err := alice.upgrade().FetchUpdate(ctx, connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: patch.GetFileName()}))
	if err != nil {
		t.Fatal(err)
	}
	g, _ := alice.upgrade().GetUpgrades(ctx, connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	p := g.Msg.GetFetchProgress()
	t.Logf("fetched %s from %s: %d bytes, state %s, verified %v", p.GetFileName(), f.Msg.GetSource(), p.GetDoneBytes(), p.GetState(), p.GetVerified())
	if p.GetState() != "done" || !p.GetVerified() || p.GetDoneBytes() != patch.GetSize() {
		t.Fatalf("the patch didn't verify: %v", p)
	}
	if _, err := alice.upgrade().DiscardUpdate(ctx, connect.NewRequest(&osadminv1.DiscardUpdateRequest{UploadId: f.Msg.GetUploadId()})); err != nil {
		t.Fatal(err)
	}

	if err := setPolicy(t, alice, &osadminv1.UpgradePolicy{Source: osadmin.SourceBuiltIn, ReleaseChannel: proto.String("stable")}); err != nil {
		t.Fatal(err)
	}
	if _, err := checkNow(alice); err != nil {
		t.Fatal(err)
	}
	st = mirrorStatus(t, alice)
	t.Logf("stable channel: picked %s", st.GetReleaseTag())
	if want := os.Getenv("GHPROOF_STABLE"); st.GetReleaseTag() != want {
		t.Fatalf("the stable channel picked %q, want %q", st.GetReleaseTag(), want)
	}
}
