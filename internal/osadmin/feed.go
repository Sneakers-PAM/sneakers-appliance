// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/mod/semver"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// The update feed (docs/upgrades.md#the-update-feed): signed static files on
// a host of the project's, <channel>/index.json with its signature, the
// built-in source. The index is the format the box already reads, plus a tag
// on each entry (the release its file is downloaded from, the same GitHub
// download as ever), the withdrawn list and the feed's own sequence. The host
// isn't trusted: the index must be signed by a feed key pinned in the build,
// and the files it names are verified as ever when they are staged. The box
// never turns to GitHub's releases for the list on its own: when the feed
// can't be taken it shows the cause and the last list it verified, or says
// there is none yet.

const (
	// feedFresh is how long a feed answer is used before the box asks again
	// on its own; Check now asks at once.
	feedFresh = 5 * time.Minute
	// feedMaxJump is how far above the last sequence taken a new one may be.
	feedMaxJump = 1000
	// feedFuture is how far ahead of the box's clock the feed's own
	// generated_at may be.
	feedFuture = 24 * time.Hour
	// maxFeedIndex caps the index read.
	maxFeedIndex = 1 << 20
)

// DefaultFeedURL is the project's update feed. A production build reads it
// once a feed key is pinned in the build (UpgradeOptions.FeedKeys).
const DefaultFeedURL = "https://updates.sneakers-pam.com"

// feedState is the last feed answer taken, and how the last ask went, for
// the status line.
type feedState struct {
	mu   sync.Mutex
	idx  updatepkg.Index
	tags map[string]string
	tag  string
	at   time.Time
	etag string
	ok   bool
	// state is ok (taken), stale (the last list kept is shown) or none (no
	// list); errText is why the last ask failed, seq and takenAt are those
	// of the list shown.
	state   string
	errText string
	seq     int64
	takenAt time.Time
}

// feedBase is the feed's address for this box, empty when it has none: no
// URL or no key pinned (a build without a feed, which the release guard
// refuses to ship), a lab build, or a lab build pointed at a test repository.
func (s *Server) feedBase() string {
	u := s.o.Upgrade
	if u.FeedURL == "" || len(u.FeedKeys) == 0 || u.Channel != release.ChannelProduction || s.labOverride(s.policy()) {
		return ""
	}
	return strings.TrimRight(u.FeedURL, "/")
}

// useFeed is whether the built-in source is the feed: the build has one, and
// the admin hasn't picked GitHub's releases.
func (s *Server) useFeed() bool {
	return s.feedBase() != "" && s.policy().Source != SourceGitHub
}

// setFeedTags makes the feed's tags the ones files are fetched from.
func (s *Server) setFeedTags(tags map[string]string, newest string) {
	s.github.mu.Lock()
	s.github.tags, s.github.tag, s.github.tagSet = tags, newest, true
	s.github.mu.Unlock()
}

// errFeedRefused marks a feed that answered but isn't taken, errFeedSignature
// one whose signature doesn't verify.
var (
	errFeedRefused   = errors.New("refused")
	errFeedMissing   = errors.New("the channel has no feed file yet")
	errFeedSignature = errors.New("the signature doesn't verify with any trusted feed key")
)

// resolveFeedOnly answers the feed's index for the built-in source: the
// verified answer when it can be taken, else the last list kept (the note says
// why, how old and which sequence), else an error saying there is no list yet.
// It never turns to GitHub.
func (s *Server) resolveFeedOnly(ctx context.Context, force bool) (updatepkg.Index, string, error) {
	channel, _ := s.releaseChannel(s.policy())
	idx, cause := s.resolveFeed(ctx, force, channel)
	if cause == "" {
		return idx, "", nil
	}
	s.feed.mu.Lock()
	defer s.feed.mu.Unlock()
	now := s.o.Clock.Now()
	s.feed.errText = "The update feed" + cause
	if kept, tags, tag, takenAt, seq, ok := s.loadFeedCache(channel, now); ok {
		s.feed.state, s.feed.seq, s.feed.takenAt = "stale", seq, takenAt
		s.setFeedTags(tags, tag)
		age := feedAge(now.Sub(takenAt))
		s.o.Logger.Warn("osadmin: showing the last update list taken", log.F("age", age), log.F("sequence", seq), log.F("cause", cause))
		return kept, fmt.Sprintf("The update feed%s; showing the last list taken %s ago (sequence %d), which may be out of date", cause, age, seq), nil
	}
	s.feed.state, s.feed.seq, s.feed.takenAt = "none", 0, time.Time{}
	return updatepkg.Index{}, "", codes.New(codes.UpgradeUpload, "there is no update list yet: the update feed%s; upload a .bin or set a mirror", cause)
}

// feedAge is a duration for a note.
func feedAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// resolveFeed asks the feed and takes its answer when it verifies; cause is ""
// then, else a clause for the notes: why it wasn't taken.
func (s *Server) resolveFeed(ctx context.Context, force bool, channel string) (idx updatepkg.Index, cause string) {
	base := s.feedBase()
	s.feed.mu.Lock()
	defer s.feed.mu.Unlock()
	now := s.o.Clock.Now()
	if !force && s.feed.ok && now.Sub(s.feed.at) < feedFresh {
		s.setFeedTags(s.feed.tags, s.feed.tag)
		return s.feed.idx, ""
	}
	hc, err := s.fetchClient(source{name: "direct", direct: true})
	if err != nil {
		s.o.Logger.Warn("osadmin: the update feed's client can't be made", log.F("error", err.Error()))
		return updatepkg.Index{}, " isn't reachable"
	}
	hc = s.githubClient(hc)
	url := base + "/" + channel + "/index.json"
	body, etag, notModified, err := s.feedGet(ctx, hc, url, s.feed.etag, force)
	if errors.Is(err, errFeedMissing) {
		s.o.Logger.Info("osadmin: the update feed has no list for the channel yet", log.F("url", url), log.F("channel", channel))
		return updatepkg.Index{}, " has no list for the " + channel + " channel yet"
	}
	if err != nil {
		s.o.Logger.Info("osadmin: the update feed isn't reachable", log.F("url", base), log.F("error", err.Error()))
		return updatepkg.Index{}, " isn't reachable"
	}
	if notModified && s.feed.ok {
		s.feed.at = now
		s.setFeedTags(s.feed.tags, s.feed.tag)
		return s.feed.idx, ""
	}
	sigs := s.feedSigs(ctx, hc, url)
	if !s.feedSigned(body, sigs, now) {
		return updatepkg.Index{}, s.feedRefused(base, channel, errFeedSignature)
	}
	taken, tags, newest, err := s.feedEntries(body, channel, now, true)
	if err != nil {
		return updatepkg.Index{}, s.feedRefused(base, channel, err)
	}
	s.feed.idx, s.feed.tags, s.feed.tag, s.feed.at, s.feed.etag, s.feed.ok = taken, tags, newest, now, etag, true
	s.feed.state, s.feed.errText, s.feed.seq, s.feed.takenAt = "ok", "", taken.Feed.Sequence, now
	s.setFeedTags(tags, newest)
	if err := s.keepFeed(channel, body, sigs, now); err != nil {
		s.o.Logger.Warn("osadmin: the update list isn't kept", log.F("error", err.Error()))
	}
	s.o.Logger.Info("osadmin: the update feed taken", log.F("channel", channel), log.F("sequence", taken.Feed.Sequence), log.F("files", len(tags)))
	return taken, ""
}

// feedRefused logs and audits a feed that answered but isn't taken, and is
// the clause for the notes.
func (s *Server) feedRefused(base, channel string, err error) string {
	s.o.Logger.Warn("osadmin: the update feed was refused", log.F("url", base), log.F("error", err.Error()))
	s.write(osaudit.Entry{Actor: "osadmin", Action: "upgrade.feed", Target: "feed", Detail: map[string]string{"url": base, "channel": channel}}, err)
	if errors.Is(err, errFeedSignature) {
		return "'s signature didn't verify"
	}
	return " was refused (" + strings.TrimPrefix(err.Error(), errFeedRefused.Error()+": ") + ")"
}

func (s *Server) feedGet(ctx context.Context, hc *http.Client, url, etag string, force bool) (body []byte, newTag string, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", false, err
	}
	if etag != "" && !force {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, etag, true, nil
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, "", false, errFeedMissing
	default:
		return nil, "", false, fmt.Errorf("%s answered %s", url, resp.Status)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxFeedIndex+1))
	if err != nil {
		return nil, "", false, err
	}
	if len(body) > maxFeedIndex {
		return nil, "", false, fmt.Errorf("%s is over %d bytes", url, maxFeedIndex)
	}
	// A static host with no file at the path can answer 200 with its own HTML
	// page; that is no list for the channel, never a list to verify.
	if t := bytes.TrimSpace(body); len(t) > 0 && t[0] == '<' {
		return nil, "", false, errFeedMissing
	}
	return body, resp.Header.Get("ETag"), false, nil
}

// feedSigs are the signatures beside the index: .sigstore.json, and a second
// at .sigstore.2.json during a key rotation.
func (s *Server) feedSigs(ctx context.Context, hc *http.Client, url string) [][]byte {
	var out [][]byte
	for _, suffix := range []string{".sigstore.json", ".sigstore.2.json"} {
		if sig, _, _, err := s.feedGet(ctx, hc, url+suffix, "", true); err == nil {
			out = append(out, sig)
		}
	}
	return out
}

// feedSigned is whether a signature verifies the index with a pinned feed
// key that hasn't expired.
func (s *Server) feedSigned(body []byte, sigs [][]byte, now time.Time) bool {
	sum := sha256.Sum256(body)
	for _, sig := range sigs {
		bd, err := sigbundle.Parse(sig)
		if err != nil {
			continue
		}
		for _, k := range s.o.Upgrade.FeedKeys {
			if !k.NotAfter.IsZero() && now.After(k.NotAfter) {
				continue
			}
			pub, err := sigbundle.ParsePublicKey(k.PEM)
			if err != nil {
				continue
			}
			if bd.Verify(pub, sum) == nil {
				return true
			}
		}
	}
	return false
}

// feedEntries checks a verified index's own rules and, when fresh, the
// sequence (kept when taken); the list kept on disk is checked again without
// the sequence, which it has already passed.
func (s *Server) feedEntries(body []byte, channel string, now time.Time, fresh bool) (updatepkg.Index, map[string]string, string, error) {
	var idx updatepkg.Index
	if err := json.Unmarshal(body, &idx); err != nil {
		return updatepkg.Index{}, nil, "", fmt.Errorf("%w: the index doesn't parse: %v", errFeedRefused, err)
	}
	switch {
	case idx.Feed == nil:
		return updatepkg.Index{}, nil, "", fmt.Errorf("%w: the index has no feed section", errFeedRefused)
	case idx.Feed.Channel != channel:
		return updatepkg.Index{}, nil, "", fmt.Errorf("%w: it is the %q feed, not %q", errFeedRefused, idx.Feed.Channel, channel)
	}
	if err := idx.ValidateWithdrawn(); err != nil {
		return updatepkg.Index{}, nil, "", fmt.Errorf("%w: %v", errFeedRefused, err)
	}
	if t, err := time.Parse(time.RFC3339, idx.Feed.GeneratedAt); err != nil || (fresh && t.After(now.Add(feedFuture))) {
		return updatepkg.Index{}, nil, "", fmt.Errorf("%w: its time %q is not a time or is too far ahead", errFeedRefused, idx.Feed.GeneratedAt)
	}
	tags := map[string]string{}
	var newest string
	for _, list := range [][]updatepkg.IndexEntry{idx.Products, idx.BaseOS, idx.BaseWeb, idx.Base} {
		for _, e := range list {
			if e.Tag == "" {
				return updatepkg.Index{}, nil, "", fmt.Errorf("%w: %s names no release", errFeedRefused, e.File)
			}
			if _, dup := tags[e.File]; !dup {
				tags[e.File] = e.Tag
			}
			if newest == "" || tagNewer(e.Tag, newest) {
				newest = e.Tag
			}
		}
	}
	if fresh {
		if err := s.takeFeedSequence(channel, idx.Feed.Sequence); err != nil {
			return updatepkg.Index{}, nil, "", err
		}
	}
	return idx, tags, newest, nil
}

// tagNewer is whether release tag a is newer than b.
func tagNewer(a, b string) bool {
	return semver.Compare("v"+strings.TrimPrefix(a, "v"), "v"+strings.TrimPrefix(b, "v")) > 0
}

const feedSequenceFile = "feed-sequence-"

// takeFeedSequence refuses a sequence below the highest taken, or far above
// it, and keeps the new one.
func (s *Server) takeFeedSequence(channel string, seq int64) error {
	path := s.ownPath(feedSequenceFile + channel)
	var last int64
	if b, err := os.ReadFile(path); err == nil { // #nosec G304 -- osadmin's own file
		last, _ = strconv.ParseInt(string(bytes.TrimSpace(b)), 10, 64)
	}
	switch {
	case seq <= 0:
		return fmt.Errorf("%w: its sequence %d isn't a sequence", errFeedRefused, seq)
	case seq < last:
		return fmt.Errorf("%w: its sequence %d goes backwards from %d", errFeedRefused, seq, last)
	case last > 0 && seq > last+feedMaxJump:
		return fmt.Errorf("%w: its sequence %d is too far ahead of %d", errFeedRefused, seq, last)
	}
	if seq == last {
		return nil
	}
	if err := os.MkdirAll(s.o.Paths.APIDir(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strconv.FormatInt(seq, 10)+"\n"), 0o600)
}

// feedCache is the last list taken, kept on disk with its signatures so it is
// verified again when it is shown.
type feedCache struct {
	TakenAt string   `json:"taken_at"`
	Index   []byte   `json:"index"`
	Sigs    [][]byte `json:"sigs"`
}

func (s *Server) feedCachePath(channel string) string {
	return s.ownPath("feed-cache-" + channel + ".json")
}

func (s *Server) keepFeed(channel string, body []byte, sigs [][]byte, now time.Time) error {
	b, err := json.Marshal(feedCache{TakenAt: now.UTC().Format(time.RFC3339), Index: body, Sigs: sigs})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.o.Paths.APIDir(), 0o700); err != nil {
		return err
	}
	return writeAtomic(s.feedCachePath(channel), b)
}

// loadFeedCache is the last list taken, when it is there and still verifies
// with a trusted feed key.
func (s *Server) loadFeedCache(channel string, now time.Time) (idx updatepkg.Index, tags map[string]string, newest string, takenAt time.Time, seq int64, ok bool) {
	raw, err := os.ReadFile(s.feedCachePath(channel)) // #nosec G304 -- osadmin's own file
	if err != nil {
		return updatepkg.Index{}, nil, "", time.Time{}, 0, false
	}
	var c feedCache
	if err := json.Unmarshal(raw, &c); err != nil || len(c.Index) == 0 {
		return updatepkg.Index{}, nil, "", time.Time{}, 0, false
	}
	t, err := time.Parse(time.RFC3339, c.TakenAt)
	if err != nil {
		return updatepkg.Index{}, nil, "", time.Time{}, 0, false
	}
	if !s.feedSigned(c.Index, c.Sigs, now) {
		s.o.Logger.Warn("osadmin: the update list kept doesn't verify; it isn't shown")
		return updatepkg.Index{}, nil, "", time.Time{}, 0, false
	}
	idx, tags, newest, err = s.feedEntries(c.Index, channel, now, false)
	if err != nil {
		return updatepkg.Index{}, nil, "", time.Time{}, 0, false
	}
	return idx, tags, newest, t, idx.Feed.Sequence, true
}

// feedStatus fills in the feed's part of the mirror status.
func (s *Server) feedStatus(out *osadminv1.MirrorStatus) {
	base := s.feedBase()
	if base == "" || !s.useFeed() {
		return
	}
	s.feed.mu.Lock()
	defer s.feed.mu.Unlock()
	out.FeedUrl, out.FeedState, out.FeedError, out.FeedSequence = base, s.feed.state, s.feed.errText, s.feed.seq
	if !s.feed.takenAt.IsZero() {
		out.FeedTakenAt = timestamppb.New(s.feed.takenAt)
	}
}
