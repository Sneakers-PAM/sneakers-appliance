// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// The GitHub source (docs/upgrades.md#the-github-source): the release
// source of the built-in list. The box lists the repository's releases
// through the API (internal/ghrelease), picks the newest of its channel
// that's finished, and fetches the index and the files from that release.
// The index and SHA256SUMS must carry a signature by the box's release
// key; every .bin is verified as from any source. When the API can't be
// read the latest stable release's files are fetched, which needs no API
// call.
package osadmin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/ghrelease"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// indexSigSuffix names the index's signature beside it on a release.
const indexSigSuffix = ".sigstore.json"

// maxIndexSig caps the index signature's size.
const maxIndexSig = 64 << 10

// sumsName is the release's signed checksums, beside the index.
const sumsName = "SHA256SUMS"

// maxSums caps SHA256SUMS's size.
const maxSums = 1 << 20

// beingPublished is the Updates page's reason for skipping a release that
// isn't finished, after its tag.
const beingPublished = " is being published"

// githubState is the GitHub source's lister and the release last picked.
// tagSet is false until a release is resolved for url; false also picks a
// release fresh instead of reusing a stale tag from a different source.
type githubState struct {
	mu     sync.Mutex
	lister *ghrelease.Lister
	url    string
	tag    string
	tagSet bool
}

// releaseURLs is the GitHub source for policy p: the repository, its
// releases page (the base the downloads are under) and the API's list.
// A lab build takes the policy's override; a production build never does.
func (s *Server) releaseURLs(p Policy) (repo, web, api string) {
	if s.labOverride(p) {
		r, _ := ghrelease.ParseRepo(p.ReleaseRepo)
		return r.String(), r.Web(), r.ListURL()
	}
	u := s.o.Upgrade
	repo, web, api = u.ReleaseRepo, u.DirectURL, u.ReleaseAPIURL
	if r, err := ghrelease.ParseRepo(repo); err == nil {
		if web == "" {
			web = r.Web()
		}
		if api == "" {
			api = r.ListURL()
		}
	}
	return repo, web, api
}

// labOverride reports whether p's repository override applies: a lab
// build, and a repository that parses.
func (s *Server) labOverride(p Policy) bool {
	return s.o.Upgrade.Channel == release.ChannelLab && p.ReleaseRepo != "" && ghrelease.ValidRepo(p.ReleaseRepo) == nil
}

func (s *Server) buildVersion() string {
	if v := s.o.Upgrade.BuildVersion; v != "" {
		return v
	}
	return release.Version
}

// releaseChannel is the channel the box follows, and whether it's the
// default (rc on a pre-release build, stable otherwise).
func (s *Server) releaseChannel(p Policy) (string, bool) {
	if ghrelease.ValidChannel(p.ReleaseChannel) {
		return p.ReleaseChannel, false
	}
	return ghrelease.ChannelFor(s.buildVersion()), true
}

func (s *Server) redirectHosts() []string {
	if h := s.o.Upgrade.RedirectHosts; h != nil {
		return h
	}
	return ghrelease.AssetHosts
}

// githubLister is the lister for api, made again when the list changes.
func (s *Server) githubLister(api string) (*ghrelease.Lister, error) {
	s.github.mu.Lock()
	defer s.github.mu.Unlock()
	if s.github.lister != nil && s.github.url == api {
		return s.github.lister, nil
	}
	hc, err := s.fetchClient(source{name: "direct", direct: true})
	if err != nil {
		return nil, err
	}
	s.github.lister = &ghrelease.Lister{HTTP: hc, URL: api, Now: s.o.Clock.Now}
	s.github.url, s.github.tag, s.github.tagSet = api, "", false
	return s.github.lister, nil
}

// forgetGitHub drops the list and the pick when the source changes.
func (s *Server) forgetGitHub() {
	s.github.mu.Lock()
	defer s.github.mu.Unlock()
	s.github.lister, s.github.url, s.github.tag, s.github.tagSet = nil, "", "", false
}

// resolveDirectIndex finds the newest release on the box's channel that's
// finished and verifies (readRelease): any other is skipped and the next
// older one tried, with no error (docs/upgrades.md#the-github-source). idx
// is read from the release it resolves to; note names each newer release
// it skipped and why, for the Updates page. The pick is cached
// (githubState.tag) so a later fetch of one of idx's files takes the same
// release.
func (s *Server) resolveDirectIndex(ctx context.Context, idxSrc source, force bool) (idx updatepkg.Index, note string, err error) {
	p := s.policy()
	repo, _, api := s.releaseURLs(p)
	channel, _ := s.releaseChannel(p)
	if api == "" {
		return s.resolveDirectLatest(ctx, idxSrc)
	}
	l, err := s.githubLister(api)
	if err != nil {
		return updatepkg.Index{}, "", err
	}
	started := time.Now()
	rels, lerr := l.Releases(ctx, force)
	candidates := ghrelease.Candidates(rels, channel)
	fields := []log.Field{log.F("repo", repo), log.F("channel", channel), log.F("releases", len(rels)), log.F("force", force), log.F("ms", time.Since(started).Milliseconds())}
	if len(candidates) == 0 {
		if lerr != nil {
			s.o.Logger.Warn("osadmin: the GitHub releases list can't be read; fetching from the latest stable release", append(fields, log.F("error", lerr.Error()))...)
			return s.resolveDirectLatest(ctx, idxSrc)
		}
		s.o.Logger.Warn("osadmin: the repository has no release on the box's channel", fields...)
		return updatepkg.Index{}, "", codes.New(codes.UpgradeUpload, "%s has no %s release yet", repo, channel)
	}
	if lerr != nil {
		s.o.Logger.Warn("osadmin: the GitHub releases list wasn't read again; using the last one", append(fields, log.F("error", lerr.Error()))...)
	}
	var (
		lastErr error
		skipped []string
	)
	for _, r := range candidates {
		idx, why, ferr := s.readRelease(ctx, idxSrc, r)
		if ferr != nil {
			s.o.Logger.Info("osadmin: the GitHub release isn't usable; trying the next one on the channel", log.F("tag", r.TagName), log.F("why", why), log.F("error", ferr.Error()))
			lastErr = ferr
			skipped = append(skipped, r.TagName+why)
			continue
		}
		s.github.mu.Lock()
		s.github.tag, s.github.tagSet = r.TagName, true
		s.github.mu.Unlock()
		s.o.Logger.Info("osadmin: GitHub release picked", append(fields, log.F("tag", r.TagName))...)
		if len(skipped) > 0 {
			note = strings.Join(skipped, "; ") + "; showing " + r.TagName
			s.o.Logger.Info("osadmin: newer GitHub releases were skipped", log.F("skipped", strings.Join(skipped, "; ")), log.F("showing", r.TagName))
		}
		return idx, note, nil
	}
	return updatepkg.Index{}, "", lastErr
}

// readRelease reads r's index when r is finished: its four signed files
// are there, the index and SHA256SUMS verify, and every file the index
// names is there. Files upload one at a time, so a release can have a
// signed index and none of its .bins; the list settles that without asking
// for a file that isn't there. why is the Updates page's reason when r
// can't be used, after its tag.
func (s *Server) readRelease(ctx context.Context, src source, r ghrelease.Release) (idx updatepkg.Index, why string, err error) {
	if m := r.Missing(src.file, src.file+indexSigSuffix, sumsName, sumsName+indexSigSuffix); len(m) > 0 {
		return updatepkg.Index{}, beingPublished, unfinished(r, m)
	}
	if idx, err = s.fetchIndexAt(ctx, src, r.TagName); err != nil {
		return updatepkg.Index{}, skipReason("index", err), err
	}
	if err = s.verifySums(ctx, src, r.TagName); err != nil {
		return updatepkg.Index{}, skipReason(sumsName, err), err
	}
	if m := r.Missing(idx.Files()...); len(m) > 0 {
		return updatepkg.Index{}, beingPublished, unfinished(r, m)
	}
	return idx, "", nil
}

func unfinished(r ghrelease.Release, missing []string) error {
	return codes.New(codes.UpgradeUpload, "%s is still being published: %s isn't there yet", r.TagName, strings.Join(missing, ", "))
}

// skipReason is the Updates page's reason for skipping a finished release
// whose file what failed: it's there and doesn't verify, or it can't be
// downloaded.
func skipReason(what string, err error) string {
	if symbolOf(err) == "UPGRADE_SIGNATURE" {
		return "'s " + what + " doesn't verify"
	}
	return "'s " + what + " can't be read"
}

// resolveDirectLatest reads the latest stable release's index, which needs
// no API call: the fallback when the API can't be read and no list was
// ever cached, or no repository is configured at all.
func (s *Server) resolveDirectLatest(ctx context.Context, idxSrc source) (updatepkg.Index, string, error) {
	idx, err := s.fetchIndexAt(ctx, idxSrc, "")
	if err != nil {
		return updatepkg.Index{}, "", err
	}
	s.github.mu.Lock()
	s.github.tag, s.github.tagSet = "", true
	s.github.mu.Unlock()
	return idx, "", nil
}

// fetchIndexAt reads and verifies the signed index from the GitHub
// source's release tagged tag ("" for the latest stable release).
func (s *Server) fetchIndexAt(ctx context.Context, src source, tag string) (updatepkg.Index, error) {
	started := time.Now()
	if tag == "" {
		src.url = src.base + "/latest/download/" + src.file
	} else {
		src.url = src.base + "/download/" + tag + "/" + src.file
	}
	resp, peer, err := s.open(ctx, src, "product index")
	var idx updatepkg.Index
	if err == nil {
		idx, err = s.readSignedIndex(ctx, src, resp.Body)
		_ = resp.Body.Close()
	}
	s.fetched(ctx, src, "product index", peer, started, 0, err)
	return idx, err
}

// pickRelease is the tag a file other than the product index is fetched
// from: the release the last index resolution (resolveDirectIndex) picked,
// so the fetch takes the same release the offer named it from. Unset
// (never resolved yet, or the source changed), it resolves one first, the
// same way a check does; force asks the API again (Check now).
func (s *Server) pickRelease(ctx context.Context, force bool) (string, error) {
	s.github.mu.Lock()
	tag, ok := s.github.tag, s.github.tagSet
	s.github.mu.Unlock()
	if ok && !force {
		return tag, nil
	}
	p := s.policy()
	_, web, api := s.releaseURLs(p)
	if api == "" {
		return "", nil
	}
	idxSrc := source{name: "direct", base: web, direct: true, file: updatepkg.IndexName}
	if _, _, err := s.resolveDirectIndex(ctx, idxSrc, force); err != nil {
		return "", err
	}
	s.github.mu.Lock()
	tag = s.github.tag
	s.github.mu.Unlock()
	return tag, nil
}

// verifySums reads SHA256SUMS from the release tagged tag and verifies its
// signature with the release key.
func (s *Server) verifySums(ctx context.Context, src source, tag string) error {
	started := time.Now()
	src.url = src.base + "/download/" + tag + "/" + sumsName
	var b []byte
	resp, peer, err := s.open(ctx, src, sumsName)
	if err == nil {
		b, err = io.ReadAll(io.LimitReader(resp.Body, maxSums))
		_ = resp.Body.Close()
		if err != nil {
			err = codes.New(codes.UpgradeUpload, "%s can't be read: %v", sumsName, err)
		}
	}
	if err == nil {
		err = s.verifySigned(ctx, src, sumsName, b)
	}
	s.fetched(ctx, src, sumsName, peer, started, int64(len(b)), err)
	return err
}

// resolve fills in a GitHub source's URL from the release picked.
func (s *Server) resolve(ctx context.Context, src source, force bool) (source, error) {
	if !src.direct {
		return src, nil
	}
	tag, err := s.pickRelease(ctx, force)
	if err != nil {
		return src, err
	}
	if tag == "" {
		src.url = src.base + "/latest/download/" + src.file
	} else {
		src.url = src.base + "/download/" + tag + "/" + src.file
	}
	return src, nil
}

// readSignedIndex reads the GitHub source's index and its signature from
// the same release, and verifies the signature with the release key
// before the index is parsed.
func (s *Server) readSignedIndex(ctx context.Context, src source, body io.Reader) (updatepkg.Index, error) {
	b, err := io.ReadAll(io.LimitReader(body, (1<<20)+1))
	if err != nil {
		return updatepkg.Index{}, codes.New(codes.UpgradeUpload, "the product index can't be read: %v", err)
	}
	if err := s.verifySigned(ctx, src, "index", b); err != nil {
		return updatepkg.Index{}, err
	}
	return updatepkg.ReadIndex(bytes.NewReader(b))
}

// verifySigned verifies b, the file what read from src, with the signature
// beside it on the same release.
func (s *Server) verifySigned(ctx context.Context, src source, what string, b []byte) error {
	sigSrc := src
	sigSrc.url += indexSigSuffix
	resp, _, err := s.open(ctx, sigSrc, what+" signature")
	if err != nil {
		return codes.New(codes.UpgradeSignature, "the %s on %s has no signature (%s); the box takes a signed %s only", what, src.base, describe(err), what)
	}
	sig, err := io.ReadAll(io.LimitReader(resp.Body, maxIndexSig))
	_ = resp.Body.Close()
	if err != nil {
		return codes.New(codes.UpgradeUpload, "the %s signature can't be read: %v", what, err)
	}
	key, err := sigbundle.ParsePublicKey(s.o.Upgrade.ReleaseKeyPEM)
	if err != nil {
		return codes.Wrap(codes.KitPinMissing, err)
	}
	bd, err := sigbundle.Parse(sig)
	if err == nil {
		err = bd.Verify(key, sha256.Sum256(b))
	}
	if err != nil {
		s.o.Logger.Warn("osadmin: a GitHub file isn't signed by this box's release key; refused", log.F("url", src.url), log.F("what", what), log.F("error", err.Error()))
		return codes.New(codes.UpgradeSignature, "the %s on %s isn't signed by this box's release key: %v", what, src.base, err)
	}
	s.o.Logger.Info("osadmin: the GitHub file's signature verified", log.F("url", src.url), log.F("what", what), log.F("bytes", len(b)))
	return nil
}

// githubClient is c for the GitHub source: redirects only to the asset
// hosts.
func (s *Server) githubClient(c *http.Client) *http.Client {
	out := *c
	out.CheckRedirect = ghrelease.CheckRedirect(s.redirectHosts())
	return &out
}

// githubStatus fills in the GitHub source's part of the mirror status.
func (s *Server) githubStatus(p Policy, out *osadminv1.MirrorStatus) {
	repo, _, _ := s.releaseURLs(p)
	out.ReleaseChannel, out.ReleaseChannelDefault = s.releaseChannel(p)
	out.ReleaseRepo = repo
	out.ReleaseRepoOverrideAllowed = s.o.Upgrade.Channel == release.ChannelLab
	s.github.mu.Lock()
	l, tag := s.github.lister, s.github.tag
	s.github.mu.Unlock()
	if l == nil {
		return
	}
	out.ReleaseTag = tag
	st := l.State()
	if !st.CheckedAt.IsZero() {
		out.ReleasesCheckedAt = timestamppb.New(st.CheckedAt)
	}
	if s.o.Clock.Now().Before(st.LimitedUntil) {
		out.RateLimitedUntil = timestamppb.New(st.LimitedUntil)
	}
}

// validReleasePolicy checks the GitHub source's settings in p.
func (s *Server) validReleasePolicy(p Policy) error {
	if p.ReleaseChannel != "" && !ghrelease.ValidChannel(p.ReleaseChannel) {
		return codes.New(codes.AccessConfirm, "the release channel is stable or rc, or empty for the default")
	}
	if p.ReleaseRepo == "" {
		return nil
	}
	if s.o.Upgrade.Channel != release.ChannelLab {
		return codes.New(codes.AccessConfirm, "the GitHub repository override is for lab builds only")
	}
	if err := ghrelease.ValidRepo(p.ReleaseRepo); err != nil {
		return codes.New(codes.AccessConfirm, "%v", err)
	}
	return nil
}
