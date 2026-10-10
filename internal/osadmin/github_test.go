// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// fakeGitHub stands in for api.github.com and github.com: the releases
// list (with an ETag), and each release's downloads, which redirect to an
// asset host as GitHub's do.
type fakeGitHub struct {
	mu       sync.Mutex
	releases []map[string]any
	assets   map[string][]byte // "<tag>/<file>"; "latest" for the latest release
	etag     string
	apiHits  int
	notMod   int
	limited  bool
	redirect string // the asset host's URL
	api      *httptest.Server
	asset    *httptest.Server
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	g := &fakeGitHub{assets: map[string][]byte{}, etag: `"v1"`}
	g.asset = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		body, ok := g.assets[strings.TrimPrefix(r.URL.Path, "/")]
		g.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(g.asset.Close)
	g.redirect = g.asset.URL
	g.api = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		switch {
		case r.URL.Path == "/repos/o/r/releases":
			g.apiHits++
			if g.limited {
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", "4102444800")
				http.Error(w, `{"message":"API rate limit exceeded"}`, http.StatusForbidden)
				return
			}
			if r.Header.Get("If-None-Match") == g.etag {
				g.notMod++
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", g.etag)
			_ = json.NewEncoder(w).Encode(g.releases)
		case strings.HasPrefix(r.URL.Path, "/o/r/releases/latest/download/"):
			http.Redirect(w, r, g.redirect+"/latest/"+strings.TrimPrefix(r.URL.Path, "/o/r/releases/latest/download/"), http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/o/r/releases/download/"):
			http.Redirect(w, r, g.redirect+"/"+strings.TrimPrefix(r.URL.Path, "/o/r/releases/download/"), http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(g.api.Close)
	return g
}

func (g *fakeGitHub) release(tag string, draft, pre bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.releases = append(g.releases, map[string]any{"tag_name": tag, "draft": draft, "prerelease": pre})
	g.etag = `"` + tag + `"`
}

// publish puts an index of bins, signed by sign, and the bins on tag.
func (g *fakeGitHub) publish(t *testing.T, tag string, sign testpki.ECKey, bins ...[]byte) {
	t.Helper()
	idx := index(t, bins...)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.assets[tag+"/"+updatepkg.IndexName] = idx
	g.assets[tag+"/"+updatepkg.IndexName+".sigstore.json"] = sign.BlobBundle(t, idx)
	for _, b := range bins {
		p, err := updatepkg.Read(strings.NewReader(string(b)), int64(len(b)))
		if err != nil {
			t.Fatal(err)
		}
		g.assets[tag+"/"+updatepkg.FileName(p.Header)] = b
	}
}

// ghBox is a production box whose GitHub source is g.
func ghBox(t *testing.T, g *fakeGitHub, mods ...func(*box, *osadmin.Options)) *box {
	t.Helper()
	assetHost, _ := url.Parse(g.asset.URL)
	return newBox(t, false, append([]func(*box, *osadmin.Options){func(b *box, o *osadmin.Options) {
		o.Upgrade.HTTPClient = g.api.Client()
		o.Upgrade.DirectURL = g.api.URL + "/o/r/releases"
		o.Upgrade.ReleaseAPIURL = g.api.URL + "/repos/o/r/releases?per_page=30"
		o.Upgrade.ReleaseRepo = "o/r"
		o.Upgrade.RedirectHosts = []string{assetHost.Host}
		o.Upgrade.BuildVersion = "0.1.0"
	}}, mods...)...)
}

func builtin(t *testing.T, br *browser, channel *string) {
	t.Helper()
	if err := setPolicy(t, br, &osadminv1.UpgradePolicy{Source: osadmin.SourceBuiltIn, ReleaseChannel: channel}); err != nil {
		t.Fatal(err)
	}
}

func productNames(r *osadminv1.CheckUpdatesResponse) []string {
	var out []string
	for _, o := range r.GetProduct() {
		out = append(out, o.GetVersion())
	}
	return out
}

// The box picks the newest release of its channel from the releases list
// (never a draft), reads that release's signed index and fetches the
// files from the same release, through GitHub's redirect.
func TestTheGitHubSourcePicksTheChannelsRelease(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	stable, rc, draft := productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"), productBin(t, b.sign, b.enc, "0.2.0-rc.1", "0.1.0"), productBin(t, b.sign, b.enc, "0.3.0", "0.1.0")
	g.release("v0.3.0", true, false)
	g.release("v0.2.0-rc.1", false, true)
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, stable)
	g.publish(t, "v0.2.0-rc.1", b.sign, rc)
	g.publish(t, "v0.3.0", b.sign, draft)
	builtin(t, alice, nil)

	c, err := checkNow(alice)
	if err != nil || c.GetSource() != "direct" || strings.Join(productNames(c), ",") != "0.1.1" {
		t.Fatalf("a stable box: %v %v", c, err)
	}
	st := mirrorStatus(t, alice)
	if st.GetReleaseChannel() != "stable" || !st.GetReleaseChannelDefault() || st.GetReleaseTag() != "v0.1.1" || st.GetReleaseRepo() != "o/r" || st.GetReleasesCheckedAt() == nil || st.GetReleaseRepoOverrideAllowed() {
		t.Fatalf("status %v", st)
	}

	builtin(t, alice, proto.String("rc"))
	if c, err = checkNow(alice); err != nil || strings.Join(productNames(c), ",") != "0.2.0-rc.1" {
		t.Fatalf("an rc box: %v %v", c, err)
	}
	if st := mirrorStatus(t, alice); st.GetReleaseChannel() != "rc" || st.GetReleaseChannelDefault() || st.GetReleaseTag() != "v0.2.0-rc.1" {
		t.Fatalf("status %v", st)
	}
	f, err := alice.upgrade().FetchUpdate(context.Background(), connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "sneakers-product-0.2.0-rc.1-amd64.bin"}))
	if err != nil || f.Msg.GetSource() != "direct" {
		t.Fatalf("fetch %v %v", f, err)
	}
	g2, _ := alice.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if p := g2.Msg.GetFetchProgress(); p.GetState() != "done" || !p.GetVerified() || p.GetDoneBytes() != int64(len(rc)) {
		t.Fatalf("the fetch %v", p)
	}
	if err := stage(alice, f.Msg.GetUploadId()); err != nil {
		t.Fatal(err)
	}

	// An rc box takes a newer stable release too.
	g.release("v0.2.0", false, false)
	g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	if c, err = checkNow(alice); err != nil || strings.Join(productNames(c), ",") != "0.2.0" {
		t.Fatalf("an rc box and a newer stable: %v %v", c, err)
	}
}

// Check now asks the API again with the list's ETag; an unchanged list is
// a 304, and the other calls use the list without asking.
func TestTheReleasesListIsCachedWithItsETag(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	builtin(t, alice, nil)
	for range 2 {
		if _, err := checkNow(alice); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := alice.upgrade().ListProductVersions(context.Background(), connect.NewRequest(&osadminv1.ListProductVersionsRequest{})); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.upgrade().FetchUpdate(context.Background(), connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "sneakers-product-0.1.1-amd64.bin"})); err != nil {
		t.Fatal(err)
	}
	if g.apiHits != 2 || g.notMod != 1 {
		t.Fatalf("API asked %d times (%d not modified), want 2 and 1", g.apiHits, g.notMod)
	}
}

// With the rate limit used up the box asks no more, and a stable box
// takes the latest release's files, which need no API call.
func TestARateLimitedBoxTakesTheLatestRelease(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.limited = true
	idx := index(t, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	g.assets["latest/"+updatepkg.IndexName] = idx
	g.assets["latest/"+updatepkg.IndexName+".sigstore.json"] = b.sign.BlobBundle(t, idx)
	builtin(t, alice, nil)
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.1.1" {
		t.Fatalf("latest: %v %v", c, err)
	}
	if _, err := checkNow(alice); err != nil {
		t.Fatal(err)
	}
	st := mirrorStatus(t, alice)
	if g.apiHits != 1 || st.GetRateLimitedUntil() == nil || st.GetReleaseTag() != "" {
		t.Fatalf("API asked %d times, status %v", g.apiHits, st)
	}
}

// The GitHub source's index must be signed by this box's release key: an
// unsigned one, or one a lab key signed, is refused.
func TestTheGitHubIndexMustBeSignedByTheReleaseKey(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", testpki.ECDSA(t), productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	builtin(t, alice, nil)
	if _, err := checkNow(alice); err == nil || !strings.Contains(err.Error(), "UPGRADE_SIGNATURE") {
		t.Fatalf("an index another key signed: %v", err)
	}
	g.mu.Lock()
	delete(g.assets, "v0.1.1/"+updatepkg.IndexName+".sigstore.json")
	g.mu.Unlock()
	if _, err := checkNow(alice); err == nil || !strings.Contains(err.Error(), "UPGRADE_SIGNATURE") {
		t.Fatalf("an unsigned index: %v", err)
	}
}

// A download may redirect only to the asset hosts.
func TestADownloadRedirectOffTheAllowListIsRefused(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	other := httptest.NewTLSServer(g.asset.Config.Handler)
	t.Cleanup(other.Close)
	g.redirect = other.URL
	builtin(t, alice, nil)
	if _, err := checkNow(alice); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("a redirect to %s: %v", other.URL, err)
	}
}

// A box running a pre-release follows rc unless told otherwise; the
// channel is stable or rc.
func TestThePreReleaseBoxDefaultsToRC(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g, func(_ *box, o *osadmin.Options) { o.Upgrade.BuildVersion = "0.2.0-rc.1" })
	alice := b.browser()
	alice.signIn("alice")
	builtin(t, alice, nil)
	if st := mirrorStatus(t, alice); st.GetReleaseChannel() != "rc" || !st.GetReleaseChannelDefault() {
		t.Fatalf("status %v", st)
	}
	symbolIn(t, setPolicy(t, alice, &osadminv1.UpgradePolicy{Source: osadmin.SourceBuiltIn, ReleaseChannel: proto.String("beta")}), connect.CodeInvalidArgument, "ACCESS_CONFIRM")
	builtin(t, alice, proto.String("stable"))
	// A policy set without the channel keeps it.
	builtin(t, alice, nil)
	if st := mirrorStatus(t, alice); st.GetReleaseChannel() != "stable" || st.GetReleaseChannelDefault() {
		t.Fatalf("kept %v", st)
	}
	builtin(t, alice, proto.String(""))
	if st := mirrorStatus(t, alice); st.GetReleaseChannel() != "rc" || !st.GetReleaseChannelDefault() {
		t.Fatalf("back to the default %v", st)
	}
}

// The GitHub repository override is a lab build's alone: a production box
// refuses to set it, and ignores one written to its policy file anyway.
func TestTheRepositoryOverrideIsForLabBuildsOnly(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	symbolIn(t, setPolicy(t, alice, &osadminv1.UpgradePolicy{Source: osadmin.SourceBuiltIn, ReleaseRepo: proto.String("someone/else")}), connect.CodeInvalidArgument, "ACCESS_CONFIRM")
	pol := map[string]any{"mode": "manual", "windowStart": "02:00", "windowMinutes": 120, "source": "builtin", "releaseRepo": "someone/else"}
	raw, _ := json.Marshal(pol)
	if err := os.MkdirAll(filepath.Join(b.state, "osadmin-api"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.state, "osadmin-api", "upgrade-policy.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if st := mirrorStatus(t, alice); st.GetReleaseRepo() != "o/r" || st.GetReleaseRepoOverrideAllowed() || strings.Contains(strings.Join(st.GetBuiltinUrls(), " "), "someone") {
		t.Fatalf("a production box took the override: %v", st)
	}

	lab := newBox(t, false, func(_ *box, o *osadmin.Options) {
		o.Upgrade.Channel, o.Upgrade.DirectURL = release.ChannelLab, ""
		o.Upgrade.BuiltinMirrors = []string{"http://192.0.2.10/mirror"}
		o.Upgrade.BuildVersion = "0.0.0-lab.20261011n-g1a2b3c4"
	})
	bob := lab.browser()
	bob.signIn("alice")
	symbolIn(t, setPolicy(t, bob, &osadminv1.UpgradePolicy{Source: osadmin.SourceBuiltIn, ReleaseRepo: proto.String("not a repo")}), connect.CodeInvalidArgument, "ACCESS_CONFIRM")
	if err := setPolicy(t, bob, &osadminv1.UpgradePolicy{Source: osadmin.SourceBuiltIn, ReleaseRepo: proto.String("example/throwaway")}); err != nil {
		t.Fatal(err)
	}
	st := mirrorStatus(t, bob)
	if st.GetReleaseRepo() != "example/throwaway" || !st.GetReleaseRepoOverrideAllowed() || st.GetReleaseChannel() != "rc" ||
		strings.Join(st.GetBuiltinUrls(), " ") != "https://github.com/example/throwaway/releases" {
		t.Fatalf("a lab box's override: %v", st)
	}
	if err := setPolicy(t, bob, &osadminv1.UpgradePolicy{Source: osadmin.SourceBuiltIn, ReleaseRepo: proto.String("")}); err != nil {
		t.Fatal(err)
	}
	if st := mirrorStatus(t, bob); st.GetReleaseRepo() != "" || strings.Join(st.GetBuiltinUrls(), " ") != "http://192.0.2.10/mirror" {
		t.Fatalf("cleared: %v", st)
	}
}
