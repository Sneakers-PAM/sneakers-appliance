// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package ghrelease finds the release a box takes its updates from on
// GitHub Releases (docs/upgrades.md#the-github-source). It lists the
// repository's releases through the unauthenticated REST API, caching the
// answer with its ETag and keeping to the rate limit, and picks the newest
// one for the box's channel: stable, or rc, which takes a newer stable too.
// Nothing in a release is trusted for being there: the index and every
// .bin it names are verified with the box's release key.
package ghrelease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/mod/semver"
)

// The channels a box follows.
const (
	Stable = "stable"
	RC     = "rc"
)

// DefaultEvery is how long a releases list is used before the box asks
// again on its own; Check now asks at once.
const DefaultEvery = 3 * time.Hour

// maxList caps the API's answer.
const maxList = 8 << 20

// AssetHosts are the hosts a release download may redirect to, beside the
// host it was asked of.
var AssetHosts = []string{"objects.githubusercontent.com", "release-assets.githubusercontent.com"}

// Release is one entry of the releases list, as far as the box reads it.
type Release struct {
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

var rcRE = regexp.MustCompile(`^-rc\.[0-9]+$`)

// ValidChannel reports whether c is a channel.
func ValidChannel(c string) bool { return c == Stable || c == RC }

// ChannelFor is the channel a box running version follows by default: rc
// for a pre-release (an rc or a lab build), stable otherwise.
func ChannelFor(version string) string {
	if semver.Prerelease("v"+version) != "" {
		return RC
	}
	return Stable
}

// Pick is the release a box on channel takes from rels: never a draft;
// for stable, the newest release not flagged prerelease whose tag has no
// pre-release part; for rc, the newest of those and the releases flagged
// prerelease whose tag ends in -rc.<n>.
func Pick(rels []Release, channel string) (Release, bool) {
	var best Release
	found := false
	for _, r := range rels {
		tag := r.TagName
		if r.Draft || semver.Canonical(tag) != tag {
			continue
		}
		pre := semver.Prerelease(tag)
		switch {
		case pre == "" && !r.Prerelease:
		case channel == RC && r.Prerelease && rcRE.MatchString(pre):
		default:
			continue
		}
		if !found || semver.Compare(tag, best.TagName) > 0 {
			best, found = r, true
		}
	}
	return best, found
}

// Previous is the release a release tagged tag patches from: the newest
// published release older than tag on tag's channel (an rc tag's channel
// takes stable releases too).
func Previous(rels []Release, tag string) (Release, bool) {
	older := make([]Release, 0, len(rels))
	for _, r := range rels {
		if semver.IsValid(r.TagName) && semver.Compare(r.TagName, tag) < 0 {
			older = append(older, r)
		}
	}
	channel := Stable
	if semver.Prerelease(tag) != "" {
		channel = RC
	}
	return Pick(older, channel)
}

// Repo is a GitHub repository, owner/name.
type Repo struct{ Owner, Name string }

var repoPartRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

// ValidRepo checks an owner/name.
func ValidRepo(s string) error {
	_, err := ParseRepo(s)
	return err
}

// ParseRepo reads an owner/name.
func ParseRepo(s string) (Repo, error) {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			o, n := s[:i], s[i+1:]
			if repoPartRE.MatchString(o) && repoPartRE.MatchString(n) && o != "." && o != ".." && n != "." && n != ".." {
				return Repo{Owner: o, Name: n}, nil
			}
			break
		}
	}
	return Repo{}, fmt.Errorf("%q isn't a GitHub repository (owner/name)", s)
}

func (r Repo) String() string { return r.Owner + "/" + r.Name }

// ListURL is the API's releases list, the newest 30.
func (r Repo) ListURL() string {
	return "https://api.github.com/repos/" + r.Owner + "/" + r.Name + "/releases?per_page=30"
}

// Web is the repository's releases page, the base its downloads are under.
func (r Repo) Web() string { return "https://github.com/" + r.Owner + "/" + r.Name + "/releases" }

// AssetURL is file's download on the release tagged tag.
func (r Repo) AssetURL(tag, file string) string {
	return r.Web() + "/download/" + url.PathEscape(tag) + "/" + url.PathEscape(file)
}

// LatestURL is file's download on the latest (stable) release, which needs
// no API call.
func (r Repo) LatestURL(file string) string {
	return r.Web() + "/latest/download/" + url.PathEscape(file)
}

// RateLimitError is the API refusing for the rate limit, until Until.
type RateLimitError struct{ Until time.Time }

func (e *RateLimitError) Error() string {
	return "the GitHub API's rate limit is used up until " + e.Until.UTC().Format(time.RFC3339)
}

// State is what the lister knows: the ETag and when the list was last
// read, and the rate limit's end when it's used up.
type State struct {
	ETag         string
	CheckedAt    time.Time
	LimitedUntil time.Time
	Releases     []Release
}

// Lister lists a repository's releases, cached.
type Lister struct {
	// HTTP makes the requests; URL is the list (Repo.ListURL).
	HTTP *http.Client
	URL  string
	// Now is the clock; nil is time.Now. Every is how long a list is used
	// before asking again; 0 is DefaultEvery.
	Now   func() time.Time
	Every time.Duration

	mu    sync.Mutex
	state State
	have  bool
}

func (l *Lister) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *Lister) every() time.Duration {
	if l.Every > 0 {
		return l.Every
	}
	return DefaultEvery
}

// State is a copy of what the lister knows.
func (l *Lister) State() State {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.state
	st.Releases = slices.Clone(st.Releases)
	return st
}

// Releases is the releases list. It's the cached list while it's newer
// than Every, unless force (Check now); otherwise the API is asked, with
// the cached list's ETag, so an unchanged list costs no rate limit. While
// the rate limit is used up nothing is asked: the cached list comes back
// (nil when there's none) with a *RateLimitError.
func (l *Lister) Releases(ctx context.Context, force bool) ([]Release, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Before(l.state.LimitedUntil) {
		return slices.Clone(l.state.Releases), &RateLimitError{Until: l.state.LimitedUntil}
	}
	if l.have && !force && now.Sub(l.state.CheckedAt) < l.every() {
		return slices.Clone(l.state.Releases), nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "sneakers-appliance")
	if l.have && l.state.ETag != "" {
		req.Header.Set("If-None-Match", l.state.ETag)
	}
	resp, err := l.HTTP.Do(req)
	if err != nil {
		return slices.Clone(l.state.Releases), err
	}
	defer func() { _ = resp.Body.Close() }()
	if until, limited := limitOf(resp, now); limited {
		l.state.LimitedUntil = until
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			return slices.Clone(l.state.Releases), &RateLimitError{Until: until}
		}
	}
	switch resp.StatusCode {
	case http.StatusNotModified:
		if !l.have {
			return nil, errors.New("the GitHub API answered 304 to a first request")
		}
		l.state.CheckedAt = now
		return slices.Clone(l.state.Releases), nil
	case http.StatusOK:
	default:
		return slices.Clone(l.state.Releases), fmt.Errorf("the GitHub API answered %s for the releases", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxList+1))
	if err != nil {
		return slices.Clone(l.state.Releases), err
	}
	if len(b) > maxList {
		return slices.Clone(l.state.Releases), fmt.Errorf("the releases list is over %d bytes", maxList)
	}
	var rels []Release
	if err := json.Unmarshal(b, &rels); err != nil {
		return slices.Clone(l.state.Releases), fmt.Errorf("the releases list doesn't parse: %w", err)
	}
	l.state.Releases, l.state.ETag, l.state.CheckedAt, l.have = rels, resp.Header.Get("ETag"), now, true
	return slices.Clone(rels), nil
}

// limitOf reads the rate limit from an answer: used up, and until when
// (the reset, or Retry-After, or a minute when neither says).
func limitOf(resp *http.Response, now time.Time) (time.Time, bool) {
	retry := resp.Header.Get("Retry-After")
	if resp.Header.Get("X-RateLimit-Remaining") != "0" && retry == "" {
		return time.Time{}, false
	}
	if s, err := strconv.Atoi(retry); err == nil && s > 0 {
		return now.Add(time.Duration(s) * time.Second), true
	}
	if s, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil && s > 0 {
		if t := time.Unix(s, 0); t.After(now) {
			return t, true
		}
	}
	return now.Add(time.Minute), true
}

// CheckRedirect is an http.Client CheckRedirect that follows at most ten
// redirects: to the host first asked, or over https to one of hosts (a
// host name alone is its default port).
func CheckRedirect(hosts []string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		u, first := req.URL, via[0].URL
		if u.Scheme == first.Scheme && u.Host == first.Host {
			return nil
		}
		if u.Scheme == "https" && slices.Contains(hosts, u.Host) {
			return nil
		}
		return fmt.Errorf("a redirect to %s://%s is refused: release downloads come only from %s or https://%v", u.Scheme, u.Host, first.Host, hosts)
	}
}
