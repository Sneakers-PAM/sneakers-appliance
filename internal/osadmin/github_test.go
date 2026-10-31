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
	redirect string          // the asset host's URL
	failing  map[string]bool // tags whose downloads answer 500
	gets     []string        // the downloads asked for, "<tag>/<file>"
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
			_ = json.NewEncoder(w).Encode(g.listed())
		case strings.HasPrefix(r.URL.Path, "/o/r/releases/latest/download/"):
			http.Redirect(w, r, g.redirect+"/latest/"+strings.TrimPrefix(r.URL.Path, "/o/r/releases/latest/download/"), http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/o/r/releases/download/"):
			file := strings.TrimPrefix(r.URL.Path, "/o/r/releases/download/")
			g.gets = append(g.gets, file)
			if g.failing[strings.SplitN(file, "/", 2)[0]] {
				http.Error(w, "unavailable", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, g.redirect+"/"+file, http.StatusFound)
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

// listed is the releases list with each release's uploaded assets, as the
// API answers it: a release with none has an empty list.
func (g *fakeGitHub) listed() []map[string]any {
	out := make([]map[string]any, 0, len(g.releases))
	for _, r := range g.releases {
		assets := []map[string]any{}
		for name := range g.assets {
			if file, ok := strings.CutPrefix(name, r["tag_name"].(string)+"/"); ok {
				assets = append(assets, map[string]any{"name": file, "state": "uploaded"})
			}
		}
		e := map[string]any{"assets": assets}
		for k, v := range r {
			e[k] = v
		}
		out = append(out, e)
	}
	return out
}

// remove takes files off tag, as a run still uploading hasn't put them
// there yet.
func (g *fakeGitHub) remove(tag string, files ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, f := range files {
		delete(g.assets, tag+"/"+f)
	}
	g.etag = `"` + tag + `-` + strings.Join(files, ",") + `"`
}

func (g *fakeGitHub) asked(tag string) []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for _, f := range g.gets {
		if strings.HasPrefix(f, tag+"/") {
			out = append(out, f)
		}
	}
	return out
}

// publish puts an index of bins and SHA256SUMS, both signed by sign, and
// the bins on tag.
func (g *fakeGitHub) publish(t *testing.T, tag string, sign testpki.ECKey, bins ...[]byte) {
	t.Helper()
	idx := index(t, bins...)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.assets[tag+"/"+updatepkg.IndexName] = idx
	g.assets[tag+"/"+updatepkg.IndexName+".sigstore.json"] = sign.BlobBundle(t, idx)
	sums := []byte("sums of " + tag + "\n")
	g.assets[tag+"/SHA256SUMS"] = sums
	g.assets[tag+"/SHA256SUMS.sigstore.json"] = sign.BlobBundle(t, sums)
	g.etag = `"` + tag + `-published"`
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

// A release can exist in the list before its files are uploaded (it's
// still being signed and published): the check skips it for the newest
// one that has files, with no error, and the Updates page says which
// release it's waiting on.
func TestUpdateCheckSkipsANewestReleaseWithNoFilesYet(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	// v0.2.0 is in the list (its draft was published) but has no assets
	// yet: the run that signs and uploads them hasn't finished.
	g.release("v0.2.0", false, false)
	builtin(t, alice, nil)

	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.1.1" {
		t.Fatalf("a release with no files yet: %v %v", c, err)
	}
	if c.GetPublishingNote() != "v0.2.0 is being published; showing v0.1.1" {
		t.Fatalf("publishing note: %q", c.GetPublishingNote())
	}
	if st := mirrorStatus(t, alice); st.GetReleaseTag() != "v0.1.1" {
		t.Fatalf("status %v", st)
	}

	// Once its files are signed and uploaded the next check picks it up.
	g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	if c, err = checkNow(alice); err != nil || strings.Join(productNames(c), ",") != "0.2.0" || c.GetPublishingNote() != "" {
		t.Fatalf("once it's published: %v %v", c, err)
	}

	// A fetch of the file the offer named takes the release it came from.
	f, err := alice.upgrade().FetchUpdate(context.Background(), connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "sneakers-product-0.2.0-amd64.bin"}))
	if err != nil || f.Msg.GetSource() != "direct" {
		t.Fatalf("fetch %v %v", f, err)
	}
}

// A release's index may be there but not verify (a bad signature, or a
// run that uploaded a corrupt file): the check skips it the same way,
// naming why on the Updates page.
func TestUpdateCheckSkipsANewestReleaseWithAnInvalidIndex(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	g.release("v0.2.0", false, false)
	g.publish(t, "v0.2.0", testpki.ECDSA(t), productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	builtin(t, alice, nil)

	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.1.1" {
		t.Fatalf("a release whose index doesn't verify: %v %v", c, err)
	}
	if c.GetPublishingNote() != "v0.2.0's index doesn't verify; showing v0.1.1" {
		t.Fatalf("publishing note: %q", c.GetPublishingNote())
	}
}

// The newest release on the channel, with its files there and signed,
// needs no fallback and no publishing note.
func TestUpdateCheckTakesTheNewestReleaseWhenItVerifies(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	builtin(t, alice, nil)
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.1.1" || c.GetPublishingNote() != "" {
		t.Fatalf("the newest, verified release: %v %v", c, err)
	}
}

// When nothing on the channel has a usable index the check fails, rather
// than silently answering an empty offer.
func TestUpdateCheckFailsWhenNoReleaseVerifies(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", testpki.ECDSA(t), productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	g.release("v0.2.0", false, false)
	builtin(t, alice, nil)
	if _, err := checkNow(alice); err == nil {
		t.Fatal("no release on the channel verifies; the check should fail")
	}
}

// The index and its signature can land before the .bins do, since a
// release's files upload one by one: an index naming a file that isn't
// there yet is the same as no index, or the offer's download would fail.
func TestUpdateCheckSkipsAReleaseStillUploadingItsFiles(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	newest := productBin(t, b.sign, b.enc, "0.2.0", "0.1.0")
	g.release("v0.2.0", false, false)
	g.publish(t, "v0.2.0", b.sign, newest)
	g.remove("v0.2.0", "sneakers-product-0.2.0-amd64.bin")
	builtin(t, alice, nil)

	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.1.1" {
		t.Fatalf("an index naming a file not there yet: %v %v", c, err)
	}
	if c.GetPublishingNote() != "v0.2.0 is being published; showing v0.1.1" {
		t.Fatalf("publishing note: %q", c.GetPublishingNote())
	}
	if _, err := alice.upgrade().FetchUpdate(context.Background(), connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "sneakers-product-0.1.1-amd64.bin"})); err != nil {
		t.Fatalf("the offer's fetch: %v", err)
	}

	g.publish(t, "v0.2.0", b.sign, newest)
	if c, err = checkNow(alice); err != nil || strings.Join(productNames(c), ",") != "0.2.0" || c.GetPublishingNote() != "" {
		t.Fatalf("once it's all there: %v %v", c, err)
	}
}

// Any of the four signed files not there yet means the release isn't
// finished, not that something is wrong with it, and nothing is downloaded
// from it to find that out.
func TestUpdateCheckSkipsAReleaseMissingASignedFile(t *testing.T) {
	for _, file := range []string{updatepkg.IndexName, updatepkg.IndexName + ".sigstore.json", "SHA256SUMS", "SHA256SUMS.sigstore.json"} {
		t.Run(file, func(t *testing.T) {
			g := newFakeGitHub(t)
			b := ghBox(t, g)
			alice := b.browser()
			alice.signIn("alice")
			g.release("v0.1.1", false, false)
			g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
			g.release("v0.2.0", false, false)
			g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
			g.remove("v0.2.0", file)
			builtin(t, alice, nil)
			c, err := checkNow(alice)
			if err != nil || strings.Join(productNames(c), ",") != "0.1.1" || c.GetPublishingNote() != "v0.2.0 is being published; showing v0.1.1" {
				t.Fatalf("no %s: %v %v", file, c, err)
			}
			if got := g.asked("v0.2.0"); len(got) != 0 {
				t.Fatalf("an unfinished release was downloaded from: %v", got)
			}
		})
	}
}

// SHA256SUMS is signed like the index, and a release whose signature on
// it doesn't verify is never offered, however good its index is.
func TestUpdateCheckSkipsAReleaseWhoseSumsDontVerify(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	g.release("v0.2.0", false, false)
	g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	g.assets["v0.2.0/SHA256SUMS.sigstore.json"] = testpki.ECDSA(t).BlobBundle(t, g.assets["v0.2.0/SHA256SUMS"])
	builtin(t, alice, nil)
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.1.1" {
		t.Fatalf("sums another key signed: %v %v", c, err)
	}
	if c.GetPublishingNote() != "v0.2.0's SHA256SUMS doesn't verify; showing v0.1.1" {
		t.Fatalf("publishing note: %q", c.GetPublishingNote())
	}
}

// The Updates page names every release skipped and why, not only the
// newest.
func TestUpdateCheckNamesEveryReleaseItSkipped(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	g.release("v0.2.0", false, false)
	g.publish(t, "v0.2.0", testpki.ECDSA(t), productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	g.release("v0.3.0", false, false)
	builtin(t, alice, nil)
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.1.1" {
		t.Fatalf("two skipped: %v %v", c, err)
	}
	if c.GetPublishingNote() != "v0.3.0 is being published; v0.2.0's index doesn't verify; showing v0.1.1" {
		t.Fatalf("publishing note: %q", c.GetPublishingNote())
	}
}

// A finished release whose download fails isn't "being published": the
// check still falls back, and says what really happened.
func TestUpdateCheckDoesntCallAFailedDownloadPublishing(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	g.release("v0.2.0", false, false)
	g.publish(t, "v0.2.0", b.sign, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	g.failing = map[string]bool{"v0.2.0": true}
	builtin(t, alice, nil)
	c, err := checkNow(alice)
	if err != nil || strings.Join(productNames(c), ",") != "0.1.1" {
		t.Fatalf("a failed download: %v %v", c, err)
	}
	if c.GetPublishingNote() != "v0.2.0's index can't be read; showing v0.1.1" {
		t.Fatalf("publishing note: %q", c.GetPublishingNote())
	}
}

// A box with no finished release to fall back to gets a failure naming
// the one it's waiting on, not an empty offer.
func TestUpdateCheckFailsWhenTheOnlyReleaseIsStillPublishing(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.2.0", false, false)
	builtin(t, alice, nil)
	if _, err := checkNow(alice); err == nil || !strings.Contains(err.Error(), "v0.2.0") {
		t.Fatalf("nothing to fall back to: %v", err)
	}
}

// Falling back never offers a step down: the older release's index is
// read, and what it lists at or below the installed version isn't offered.
func TestFallingBackNeverOffersADowngrade(t *testing.T) {
	g := newFakeGitHub(t)
	b := ghBox(t, g)
	alice := b.browser()
	alice.signIn("alice")
	alice.installProduct(t, "0.1.1")
	g.release("v0.1.0", false, false)
	g.publish(t, "v0.1.0", b.sign, productBin(t, b.sign, b.enc, "0.1.0", "0.1.0"))
	g.release("v0.2.0", false, false)
	builtin(t, alice, nil)
	c, err := checkNow(alice)
	if err != nil || len(c.GetProduct()) != 0 || c.GetPublishingNote() != "v0.2.0 is being published; showing v0.1.0" {
		t.Fatalf("a fallback below the installed version: %v %v", c, err)
	}
}

// mirrorThenGitHub is a box whose built-in list is a mirror, then g.
func mirrorThenGitHub(t *testing.T, g *fakeGitHub, m *files) *box {
	t.Helper()
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return ghBox(t, g, func(_ *box, o *osadmin.Options) { o.Upgrade.BuiltinMirrors = []string{srv.URL} })
}

// A mirror that hasn't got the release yet is the next source's turn,
// with the GitHub source's own fallback and note still working behind it.
func TestAMirrorWithNoIndexYetFallsToTheGitHubSource(t *testing.T) {
	g := newFakeGitHub(t)
	b := mirrorThenGitHub(t, g, &files{m: map[string][]byte{}})
	alice := b.browser()
	alice.signIn("alice")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, productBin(t, b.sign, b.enc, "0.1.1", "0.1.0"))
	g.release("v0.2.0", false, false)
	builtin(t, alice, nil)
	c, err := checkNow(alice)
	if err != nil || c.GetSource() != "direct" || strings.Join(productNames(c), ",") != "0.1.1" || c.GetPublishingNote() != "v0.2.0 is being published; showing v0.1.1" {
		t.Fatalf("an empty mirror: %v %v", c, err)
	}
}

// A mirror's index is a menu: it has no release list to check against, so
// a file it hasn't got yet is found when it's fetched, from the next
// source, and nothing fetched is trusted until it's verified.
func TestAPartlySyncedMirrorsFetchFallsToTheGitHubSource(t *testing.T) {
	g := newFakeGitHub(t)
	m := &files{m: map[string][]byte{}}
	b := mirrorThenGitHub(t, g, m)
	alice := b.browser()
	alice.signIn("alice")
	bin := productBin(t, b.sign, b.enc, "0.1.1", "0.1.0")
	g.release("v0.1.1", false, false)
	g.publish(t, "v0.1.1", b.sign, bin)
	m.put(updatepkg.IndexName, index(t, bin))
	builtin(t, alice, nil)
	c, err := checkNow(alice)
	if err != nil || c.GetSource() != osadmin.SourceBuiltIn || strings.Join(productNames(c), ",") != "0.1.1" || c.GetPublishingNote() != "" {
		t.Fatalf("a mirror's index: %v %v", c, err)
	}
	f, err := alice.upgrade().FetchUpdate(context.Background(), connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "sneakers-product-0.1.1-amd64.bin"}))
	if err != nil || f.Msg.GetSource() != "direct" {
		t.Fatalf("the fetch: %v %v", f, err)
	}
}

// A mirror lagging behind the box offers nothing older than what's
// installed.
func TestAStaleMirrorNeverOffersADowngrade(t *testing.T) {
	g := newFakeGitHub(t)
	m := &files{m: map[string][]byte{}}
	b := mirrorThenGitHub(t, g, m)
	alice := b.browser()
	alice.signIn("alice")
	alice.installProduct(t, "0.1.1")
	m.put(updatepkg.IndexName, index(t, productBin(t, b.sign, b.enc, "0.1.0", "0.1.0")))
	builtin(t, alice, nil)
	if c, err := checkNow(alice); err != nil || len(c.GetProduct()) != 0 {
		t.Fatalf("a stale mirror: %v %v", c, err)
	}
}
