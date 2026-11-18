// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// boxNow is the test box's clock.
var boxNow = time.Unix(1791208800, 0)

// feedBox is a production box whose update feed is the fake host, trusting
// feedKey for it, with the fake GitHub's releases behind it as the fallback.
func feedBox(t *testing.T, g *fakeGitHub, feedKey testpki.ECKey, mods ...func(*box, *osadmin.Options)) (*box, *browser) {
	t.Helper()
	b := ghBox(t, g, append([]func(*box, *osadmin.Options){func(_ *box, o *osadmin.Options) {
		o.Upgrade.FeedURL = g.api.URL + "/feed"
		o.Upgrade.FeedKeys = []osadmin.FeedKey{{PEM: feedKey.PublicPEM}}
	}}, mods...)...)
	alice := b.browser()
	alice.signIn("alice")
	return b, alice
}

// feedIndex is a feed index over the products (version, release tag) the test
// names, with the feed's own fields.
func feedIndex(t *testing.T, b *box, sequence int64, at time.Time, withdrawn []updatepkg.Withdrawn, products ...[2]string) []byte {
	t.Helper()
	idx := updatepkg.Index{Format: 2, Withdrawn: withdrawn, Feed: &updatepkg.FeedMeta{Channel: "rc", Sequence: sequence, GeneratedAt: at.UTC().Format(time.RFC3339)}}
	for _, p := range products {
		bin := productBin(t, b.sign, b.enc, p[0], "0.1.0")
		h, err := updatepkg.Read(strings.NewReader(string(bin)), int64(len(bin)))
		if err != nil {
			t.Fatal(err)
		}
		e := updatepkg.EntryOf(h.Header, int64(len(bin)))
		e.Tag = p[1]
		idx.Products = append(idx.Products, e)
	}
	out, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func serveFeed(g *fakeGitHub, sign testpki.ECKey, t *testing.T, index []byte) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.feed == nil {
		g.feed = map[string][]byte{}
	}
	g.feed["rc/index.json"] = index
	g.feed["rc/index.json.sigstore.json"] = sign.BlobBundle(t, index)
}

// The feed is the built-in source: its offers come with no call to GitHub's
// releases list and no index or checksum fetched from a release, each file is
// fetched from the release its entry names, and its withdrawn list applies.
func TestTheFeedIsTheBuiltInSource(t *testing.T) {
	g := newFakeGitHub(t)
	feedKey := testpki.ECDSA(t)
	b, alice := feedBox(t, g, feedKey)
	for _, v := range []string{"0.1.1", "0.2.0"} {
		g.publish(t, "v"+v, b.sign, productBin(t, b.sign, b.enc, v, "0.1.0"))
	}
	serveFeed(g, feedKey, t, feedIndex(t, b, 5, boxNow, []updatepkg.Withdrawn{{Kind: "product", Version: "0.1.1", Reason: "it fails", Use: "0.2.0"}}, [2]string{"0.2.0", "v0.2.0"}, [2]string{"0.1.1", "v0.1.1"}))
	builtin(t, alice, proto.String("rc"))
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.2.0" || c.GetPublishingNote() != "" {
		t.Fatalf("the feed's offers: %v %v", c, err)
	}
	if c.GetProduct()[0].GetReleaseTag() != "v0.2.0" || len(c.GetWithdrawn()) != 1 || c.GetWithdrawn()[0].GetVersion() != "0.1.1" {
		t.Fatalf("tag and withdrawn: %v", c)
	}
	if _, err := alice.upgrade().FetchUpdate(context.Background(), connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "sneakers-product-0.2.0-amd64.bin"})); err != nil {
		t.Fatalf("fetch from the release the entry names: %v", err)
	}
	noGitHubIndex(t, g)
	if got := g.asked("v0.2.0"); len(got) == 0 || !strings.HasSuffix(got[len(got)-1], "sneakers-product-0.2.0-amd64.bin") {
		t.Fatalf("the file wasn't fetched from its release: %v", g.gets)
	}
}

// noGitHubIndex asserts the box asked GitHub for no release list and no index
// or checksum file of a release: only .bin downloads may have come from it.
func noGitHubIndex(t *testing.T, g *fakeGitHub) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.apiHits != 0 {
		t.Fatalf("GitHub's releases list was asked %d times in the feed's path", g.apiHits)
	}
	for _, f := range g.gets {
		if !strings.HasSuffix(f, ".bin") {
			t.Fatalf("a release's index or checksums were fetched from GitHub in the feed's path: %s (%v)", f, g.gets)
		}
	}
}

// takeFeed serves a good feed and takes it once, so the box has a list to
// keep.
func takeFeed(t *testing.T, g *fakeGitHub, b *box, alice *browser, feedKey testpki.ECKey) {
	t.Helper()
	g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	serveFeed(g, feedKey, t, feedIndex(t, b, 5, boxNow, nil, [2]string{"0.2.0", "v0.2.0"}))
	builtin(t, alice, proto.String("rc"))
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.2.0" {
		t.Fatalf("the first feed: %v %v", c, err)
	}
}

// With the feed down (or the file missing) the box shows the last list it
// verified, says why, how old it is and its sequence, and never goes to GitHub.
func TestAFeedThatIsDownShowsTheLastListTaken(t *testing.T) {
	g := newFakeGitHub(t)
	feedKey := testpki.ECDSA(t)
	b, alice := feedBox(t, g, feedKey)
	takeFeed(t, g, b, alice, feedKey)
	g.feedDown = true
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.2.0" {
		t.Fatalf("the stale list: %v %v", c, err)
	}
	for _, want := range []string{"update feed isn't reachable", "last list taken", "sequence 5", "out of date"} {
		if !strings.Contains(c.GetPublishingNote(), want) {
			t.Fatalf("the note %q doesn't say %q", c.GetPublishingNote(), want)
		}
	}
	// A missing feed file is the same.
	g.feedDown = false
	g.mu.Lock()
	delete(g.feed, "rc/index.json")
	g.mu.Unlock()
	c, err = checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.2.0" || !strings.Contains(c.GetPublishingNote(), "isn't reachable") {
		t.Fatalf("a missing feed: %v %v", c, err)
	}
	if st := mirrorStatus(t, alice); st.GetFeedState() != "stale" || st.GetFeedSequence() != 5 || st.GetFeedError() == "" || st.GetFeedTakenAt() == nil {
		t.Fatalf("the feed's status: %v", st)
	}
	noGitHubIndex(t, g)
}

// With no list ever taken the box says there is none yet, and how to go on.
func TestAFeedThatIsDownWithNoListSaysThereIsNoneYet(t *testing.T) {
	g := newFakeGitHub(t)
	feedKey := testpki.ECDSA(t)
	b, alice := feedBox(t, g, feedKey)
	githubReleases(t, g, b)
	g.feedDown = true
	builtin(t, alice, proto.String("rc"))
	_, err := checkNow(alice)
	if err == nil || !strings.Contains(err.Error(), "no update list yet") || !strings.Contains(err.Error(), "upload a .bin or set a mirror") {
		t.Fatalf("no list: %v", err)
	}
	if st := mirrorStatus(t, alice); st.GetFeedState() != "none" || st.GetFeedError() == "" {
		t.Fatalf("the feed's status: %v", st)
	}
	noGitHubIndex(t, g)
}

// A feed signed by a key the box doesn't trust is refused, loudly; the list
// already taken stays, and is shown.
func TestAFeedWithABadSignatureKeepsTheListTaken(t *testing.T) {
	g := newFakeGitHub(t)
	feedKey := testpki.ECDSA(t)
	b, alice := feedBox(t, g, feedKey)
	takeFeed(t, g, b, alice, feedKey)
	serveFeed(g, testpki.ECDSA(t), t, feedIndex(t, b, 6, boxNow, nil, [2]string{"9.9.9", "v9.9.9"}))
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.2.0" || !strings.Contains(c.GetPublishingNote(), "signature didn't verify") {
		t.Fatalf("a forged feed: %v %v", c, err)
	}
	noGitHubIndex(t, g)
}

// With nothing taken, a feed that doesn't verify leaves no list at all.
func TestAFeedWithABadSignatureAndNoListLeavesNone(t *testing.T) {
	g := newFakeGitHub(t)
	feedKey := testpki.ECDSA(t)
	b, alice := feedBox(t, g, feedKey)
	githubReleases(t, g, b)
	serveFeed(g, testpki.ECDSA(t), t, feedIndex(t, b, 5, boxNow, nil, [2]string{"9.9.9", "v9.9.9"}))
	builtin(t, alice, proto.String("rc"))
	_, err := checkNow(alice)
	if err == nil || !strings.Contains(err.Error(), "no update list yet") || !strings.Contains(err.Error(), "signature didn't verify") {
		t.Fatalf("a forged feed and no list: %v", err)
	}
	noGitHubIndex(t, g)
}

// The release key doesn't sign the feed.
func TestTheReleaseKeyDoesNotSignTheFeed(t *testing.T) {
	g := newFakeGitHub(t)
	feedKey := testpki.ECDSA(t)
	b, alice := feedBox(t, g, feedKey)
	serveFeed(g, b.sign, t, feedIndex(t, b, 5, boxNow, nil, [2]string{"9.9.9", "v9.9.9"}))
	builtin(t, alice, proto.String("rc"))
	if _, err := checkNow(alice); err == nil || !strings.Contains(err.Error(), "signature didn't verify") {
		t.Fatalf("a feed signed with the release key: %v", err)
	}
}

// A feed whose sequence goes backwards is refused (it could undo a
// withdrawal), one that jumps far ahead too (it could lock the real one out),
// and the list taken stays; the same or the next sequence is taken.
func TestTheFeedsSequenceNeverGoesBackwardsOrFarAhead(t *testing.T) {
	g := newFakeGitHub(t)
	feedKey := testpki.ECDSA(t)
	b, alice := feedBox(t, g, feedKey)
	takeFeed(t, g, b, alice, feedKey)
	g.publish(t, "v0.3.0", b.sign, productBin(t, b.sign, b.enc, "0.3.0", "0.1.0"))
	take := func(seq int64) *osadminv1.CheckUpdatesResponse {
		serveFeed(g, feedKey, t, feedIndex(t, b, seq, boxNow, nil, [2]string{"0.3.0", "v0.3.0"}))
		c, err := checkNow(alice)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := take(4); strings.Join(productNames(c), ",") != "0.2.0" || !strings.Contains(c.GetPublishingNote(), "goes backwards") {
		t.Fatalf("sequence 4 after 5: %v", c)
	}
	if c := take(5000); strings.Join(productNames(c), ",") != "0.2.0" || !strings.Contains(c.GetPublishingNote(), "too far ahead") {
		t.Fatalf("sequence 5000 after 5: %v", c)
	}
	if c := take(6); strings.Join(productNames(c), ",") != "0.3.0" || c.GetPublishingNote() != "" {
		t.Fatalf("the next sequence: %v", c)
	}
	noGitHubIndex(t, g)
}

// A feed key past its expiry no longer verifies the feed; the list taken
// while it was trusted is no longer shown either.
func TestAFeedKeyPastItsExpiryIsNotTrusted(t *testing.T) {
	g := newFakeGitHub(t)
	feedKey := testpki.ECDSA(t)
	b, alice := feedBox(t, g, feedKey, func(_ *box, o *osadmin.Options) {
		o.Upgrade.FeedKeys = []osadmin.FeedKey{{PEM: feedKey.PublicPEM, NotAfter: time.Unix(1, 0)}}
	})
	serveFeed(g, feedKey, t, feedIndex(t, b, 5, boxNow, nil, [2]string{"9.9.9", "v9.9.9"}))
	builtin(t, alice, proto.String("rc"))
	if _, err := checkNow(alice); err == nil || !strings.Contains(err.Error(), "no update list yet") {
		t.Fatalf("an expired key: %v", err)
	}
}

// During a rotation the feed carries a second signature, by the next key, and
// the box takes it with either key trusted.
func TestARotatedFeedKeyVerifiesTheSecondSignature(t *testing.T) {
	g := newFakeGitHub(t)
	oldKey, newKey := testpki.ECDSA(t), testpki.ECDSA(t)
	b, alice := feedBox(t, g, oldKey, func(_ *box, o *osadmin.Options) {
		o.Upgrade.FeedKeys = []osadmin.FeedKey{{PEM: oldKey.PublicPEM, NotAfter: time.Unix(1, 0)}, {PEM: newKey.PublicPEM}}
	})
	g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	idx := feedIndex(t, b, 5, boxNow, nil, [2]string{"0.2.0", "v0.2.0"})
	serveFeed(g, oldKey, t, idx)
	g.mu.Lock()
	g.feed["rc/index.json.sigstore.2.json"] = newKey.BlobBundle(t, idx)
	g.mu.Unlock()
	builtin(t, alice, proto.String("rc"))
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.2.0" {
		t.Fatalf("the second signature: %v %v", c, err)
	}
}

// GitHub's releases are a source the admin picks, and then the feed isn't
// asked.
func TestGitHubIsASourceTheAdminPicks(t *testing.T) {
	g := newFakeGitHub(t)
	feedKey := testpki.ECDSA(t)
	b, alice := feedBox(t, g, feedKey)
	githubReleases(t, g, b)
	serveFeed(g, feedKey, t, feedIndex(t, b, 5, boxNow, nil, [2]string{"9.9.9", "v9.9.9"}))
	if err := setPolicy(t, alice, &osadminv1.UpgradePolicy{Source: osadmin.SourceGitHub, ReleaseChannel: proto.String("rc")}); err != nil {
		t.Fatal(err)
	}
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.1.1" {
		t.Fatalf("GitHub's releases: %v %v", c, err)
	}
	if g.feedHits != 0 {
		t.Fatalf("the feed was asked %d times with GitHub picked", g.feedHits)
	}
}

// A list kept on disk that no longer verifies (changed, or signed by a key
// that is gone) is not shown.
func TestAChangedListOnDiskIsNotShown(t *testing.T) {
	g := newFakeGitHub(t)
	feedKey := testpki.ECDSA(t)
	b, alice := feedBox(t, g, feedKey)
	takeFeed(t, g, b, alice, feedKey)
	cache := filepath.Join(b.state, "osadmin-api", "feed-cache-rc.json")
	raw, err := os.ReadFile(cache)
	if err != nil {
		t.Fatalf("the list isn't kept: %v", err)
	}
	if err := os.WriteFile(cache, []byte(strings.Replace(string(raw), `"index"`, `"index":"AAAA","x"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	g.feedDown = true
	if _, err := checkNow(alice); err == nil || !strings.Contains(err.Error(), "no update list yet") {
		t.Fatalf("a changed list: %v", err)
	}
}

func githubReleases(t *testing.T, g *fakeGitHub, b *box) {
	t.Helper()
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
}
