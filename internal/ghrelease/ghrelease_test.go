// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package ghrelease_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/ghrelease"
)

func rel(tag string, draft, pre bool) ghrelease.Release {
	return ghrelease.Release{TagName: tag, Draft: draft, Prerelease: pre}
}

func TestPickByChannel(t *testing.T) {
	for _, c := range []struct {
		name    string
		rels    []ghrelease.Release
		channel string
		want    string
	}{
		{"stable takes the newest stable", []ghrelease.Release{rel("v0.1.0", false, false), rel("v0.2.0", false, false), rel("v0.3.0-rc.1", false, true)}, ghrelease.Stable, "v0.2.0"},
		{"rc takes a newer rc", []ghrelease.Release{rel("v0.1.0", false, false), rel("v0.2.0-rc.2", false, true), rel("v0.2.0-rc.1", false, true)}, ghrelease.RC, "v0.2.0-rc.2"},
		{"rc takes a newer stable", []ghrelease.Release{rel("v0.2.0-rc.2", false, true), rel("v0.2.0", false, false)}, ghrelease.RC, "v0.2.0"},
		{"drafts are never taken", []ghrelease.Release{rel("v0.1.0", false, false), rel("v0.9.0", true, false), rel("v0.9.0-rc.1", true, true)}, ghrelease.RC, "v0.1.0"},
		{"stable skips a prerelease-flagged plain tag", []ghrelease.Release{rel("v0.1.0", false, false), rel("v0.2.0", false, true)}, ghrelease.Stable, "v0.1.0"},
		{"rc skips a prerelease-flagged plain tag", []ghrelease.Release{rel("v0.1.0", false, false), rel("v0.2.0", false, true)}, ghrelease.RC, "v0.1.0"},
		{"stable skips a suffixed tag not flagged prerelease", []ghrelease.Release{rel("v0.1.0", false, false), rel("v0.2.0-rc.1", false, false)}, ghrelease.Stable, "v0.1.0"},
		{"rc skips other pre-release kinds", []ghrelease.Release{rel("v0.1.0", false, false), rel("v0.2.0-beta.1", false, true), rel("v0.2.0-rc.1.x", false, true)}, ghrelease.RC, "v0.1.0"},
		{"rc compares rc numbers as numbers", []ghrelease.Release{rel("v0.2.0-rc.9", false, true), rel("v0.2.0-rc.10", false, true)}, ghrelease.RC, "v0.2.0-rc.10"},
		{"tags that aren't versions are skipped", []ghrelease.Release{rel("latest", false, false), rel("v1", false, false), rel("v0.1.0", false, false)}, ghrelease.Stable, "v0.1.0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ghrelease.Pick(c.rels, c.channel)
			if !ok || got.TagName != c.want {
				t.Fatalf("Pick = %q %v, want %q", got.TagName, ok, c.want)
			}
		})
	}
	if _, ok := ghrelease.Pick([]ghrelease.Release{rel("v0.2.0-rc.1", false, true), rel("v0.3.0", true, false)}, ghrelease.Stable); ok {
		t.Fatal("stable picked from only an rc and a draft")
	}
}

func TestChannelFor(t *testing.T) {
	for v, want := range map[string]string{"0.1.0": ghrelease.Stable, "0.1.0-rc.1": ghrelease.RC, "0.0.0-lab.20261009m-g79c3ceb": ghrelease.RC} {
		if got := ghrelease.ChannelFor(v); got != want {
			t.Errorf("ChannelFor(%q) = %q, want %q", v, got, want)
		}
	}
}

func TestParseRepo(t *testing.T) {
	for _, ok := range []string{"Sneakers-PAM/sneakers-appliance", "a/b", "team_1/repo-x"} {
		if err := ghrelease.ValidRepo(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a", "a/b/c", "../x", "a/..", "https://github.com/a/b", "a/b?x", "a b/c"} {
		if err := ghrelease.ValidRepo(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	r := ghrelease.Repo{Owner: "o", Name: "r"}
	if r.ListURL() != "https://api.github.com/repos/o/r/releases?per_page=30" || r.AssetURL("v1.0.0", "f.json") != "https://github.com/o/r/releases/download/v1.0.0/f.json" ||
		r.LatestURL("f.json") != "https://github.com/o/r/releases/latest/download/f.json" {
		t.Fatalf("urls %s %s %s", r.ListURL(), r.AssetURL("v1.0.0", "f.json"), r.LatestURL("f.json"))
	}
}

// api is a fake releases endpoint: it counts the requests, answers 304 to
// a matching If-None-Match, and can be rate limited.
type api struct {
	mu       sync.Mutex
	hits     int
	body     string
	etag     string
	limited  bool
	reset    time.Time
	lastINM  string
	retryHdr string
}

func (a *api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hits++
	a.lastINM = r.Header.Get("If-None-Match")
	if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("User-Agent") == "" {
		http.Error(w, "headers", http.StatusBadRequest)
		return
	}
	if a.limited {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(a.reset.Unix(), 10))
		if a.retryHdr != "" {
			w.Header().Set("Retry-After", a.retryHdr)
		}
		http.Error(w, `{"message":"API rate limit exceeded"}`, http.StatusForbidden)
		return
	}
	w.Header().Set("X-RateLimit-Remaining", "59")
	if a.etag != "" && r.Header.Get("If-None-Match") == a.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", a.etag)
	_, _ = w.Write([]byte(a.body))
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newLister(t *testing.T, a *api, clk *fakeClock) *ghrelease.Lister {
	t.Helper()
	ts := httptest.NewServer(a)
	t.Cleanup(ts.Close)
	return &ghrelease.Lister{HTTP: ts.Client(), URL: ts.URL + "/repos/o/r/releases?per_page=30", Now: clk.now, Every: 3 * time.Hour}
}

const twoReleases = `[{"tag_name":"v0.2.0-rc.1","draft":false,"prerelease":true},{"tag_name":"v0.1.0","draft":false,"prerelease":false}]`

func TestListerCachesWithTheETag(t *testing.T) {
	a := &api{body: twoReleases, etag: `"abc"`}
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := newLister(t, a, clk)
	ctx := context.Background()
	rels, err := l.Releases(ctx, false)
	if err != nil || len(rels) != 2 || a.hits != 1 || a.lastINM != "" {
		t.Fatalf("first list: %v %v hits=%d inm=%q", rels, err, a.hits, a.lastINM)
	}
	// Within the interval nothing is asked.
	clk.t = clk.t.Add(time.Hour)
	if rels, err = l.Releases(ctx, false); err != nil || len(rels) != 2 || a.hits != 1 {
		t.Fatalf("cached list: %v %v hits=%d", rels, err, a.hits)
	}
	// Check now asks again, conditionally, and a 304 keeps the list.
	if rels, err = l.Releases(ctx, true); err != nil || len(rels) != 2 || a.hits != 2 || a.lastINM != `"abc"` {
		t.Fatalf("forced list: %v %v hits=%d inm=%q", rels, err, a.hits, a.lastINM)
	}
	// After the interval it asks on its own, and takes a changed list.
	a.body, a.etag = `[{"tag_name":"v0.2.0","draft":false,"prerelease":false}]`, `"def"`
	clk.t = clk.t.Add(4 * time.Hour)
	if rels, err = l.Releases(ctx, false); err != nil || len(rels) != 1 || rels[0].TagName != "v0.2.0" || a.hits != 3 {
		t.Fatalf("refreshed list: %v %v hits=%d", rels, err, a.hits)
	}
	if st := l.State(); st.ETag != `"def"` || !st.CheckedAt.Equal(clk.t) {
		t.Fatalf("state %+v", st)
	}
}

func TestListerHonoursTheRateLimit(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	a := &api{body: twoReleases, etag: `"abc"`}
	l := newLister(t, a, clk)
	ctx := context.Background()
	if _, err := l.Releases(ctx, false); err != nil {
		t.Fatal(err)
	}
	a.limited, a.reset = true, clk.t.Add(30*time.Minute)
	clk.t = clk.t.Add(4 * time.Hour)
	a.reset = clk.t.Add(30 * time.Minute)
	// Limited: the last list is kept, with the limit named.
	rels, err := l.Releases(ctx, true)
	var rl *ghrelease.RateLimitError
	if !errors.As(err, &rl) || !rl.Until.Equal(a.reset) || len(rels) != 2 {
		t.Fatalf("limited: %v %v", rels, err)
	}
	// Until the reset nothing more is asked, even by Check now.
	hits := a.hits
	clk.t = clk.t.Add(10 * time.Minute)
	if _, err := l.Releases(ctx, true); !errors.As(err, &rl) || a.hits != hits {
		t.Fatalf("asked during the limit: hits %d -> %d, %v", hits, a.hits, err)
	}
	// After the reset it asks again.
	a.limited = false
	clk.t = a.reset.Add(time.Second)
	if _, err := l.Releases(ctx, true); err != nil || a.hits != hits+1 {
		t.Fatalf("after the reset: %v hits %d", err, a.hits)
	}
}

func TestListerTakesRetryAfter(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	a := &api{limited: true, retryHdr: "120"}
	a.reset = time.Time{}
	l := newLister(t, a, clk)
	_, err := l.Releases(context.Background(), true)
	var rl *ghrelease.RateLimitError
	if !errors.As(err, &rl) || !rl.Until.Equal(clk.t.Add(120*time.Second)) {
		t.Fatalf("retry-after: %v", err)
	}
}

func TestListerRefusesABadAnswer(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	for name, body := range map[string]string{"not JSON": "<html>", "not a list": `{"tag_name":"v1.0.0"}`} {
		a := &api{body: body}
		l := newLister(t, a, clk)
		if _, err := l.Releases(context.Background(), true); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", http.StatusInternalServerError) }))
	defer ts.Close()
	l := &ghrelease.Lister{HTTP: ts.Client(), URL: ts.URL, Now: clk.now}
	if _, err := l.Releases(context.Background(), true); err == nil {
		t.Fatal("a 500 accepted")
	}
}

func TestRedirectHosts(t *testing.T) {
	check := ghrelease.CheckRedirect(ghrelease.AssetHosts)
	from, _ := url.Parse("https://github.com/o/r/releases/download/v1/f.bin")
	via := []*http.Request{{URL: from}}
	for _, ok := range []string{
		"https://objects.githubusercontent.com/github-production-release-asset/1?x=y",
		"https://release-assets.githubusercontent.com/github-production-release-asset/1?x=y",
		"https://github.com/o/r/releases/download/v1/f.bin",
	} {
		u, _ := url.Parse(ok)
		if err := check(&http.Request{URL: u}, via); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"https://evil.example.org/f.bin",
		"http://objects.githubusercontent.com/f.bin",
		"https://objects.githubusercontent.com.evil.example.org/f.bin",
		"https://githubusercontent.com/f.bin",
		"https://objects.githubusercontent.com:8443/f.bin",
	} {
		u, _ := url.Parse(bad)
		if err := check(&http.Request{URL: u}, via); err == nil {
			t.Errorf("%s allowed", bad)
		}
	}
	long := make([]*http.Request, 10)
	for i := range long {
		long[i] = &http.Request{URL: from}
	}
	if err := check(&http.Request{URL: from}, long); err == nil {
		t.Error("an eleventh redirect allowed")
	}
}

func TestPreviousOnTheSameChannel(t *testing.T) {
	rels := []ghrelease.Release{rel("v0.1.0", false, false), rel("v0.2.0-rc.1", false, true), rel("v0.2.0-rc.2", true, true), rel("v0.2.0-rc.3", false, true), rel("v0.3.0", false, false)}
	for tag, want := range map[string]string{
		"v0.2.0-rc.3": "v0.2.0-rc.1", // the draft isn't published
		"v0.2.0-rc.4": "v0.2.0-rc.3",
		"v0.2.0":      "v0.1.0", // a stable release's previous is stable
		"v0.3.1-rc.1": "v0.3.0", // an rc's previous may be stable
		"v0.4.0":      "v0.3.0",
	} {
		if got, ok := ghrelease.Previous(rels, tag); !ok || got.TagName != want {
			t.Errorf("Previous(%s) = %q %v, want %s", tag, got.TagName, ok, want)
		}
	}
	if _, ok := ghrelease.Previous(rels, "v0.1.0"); ok {
		t.Error("the first release has a previous one")
	}
}
