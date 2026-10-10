// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// The GitHub source (docs/upgrades.md#the-github-source): the release
// source of the built-in list. The box lists the repository's releases
// through the API (internal/ghrelease), picks the newest of its channel,
// and fetches the index and the files from that release. The index must
// carry a signature by the box's release key; every .bin is verified as
// from any source. When the API can't be read the latest stable release's
// files are fetched, which needs no API call.
package osadmin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
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

// githubState is the GitHub source's lister and the release last picked.
type githubState struct {
	mu     sync.Mutex
	lister *ghrelease.Lister
	url    string
	tag    string
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
	s.github.url, s.github.tag = api, ""
	return s.github.lister, nil
}

// forgetGitHub drops the list and the pick when the source changes.
func (s *Server) forgetGitHub() {
	s.github.mu.Lock()
	defer s.github.mu.Unlock()
	s.github.lister, s.github.url, s.github.tag = nil, "", ""
}

// pickRelease is the tag the GitHub source fetches from, or "" for the
// latest stable release (no API configured, or the API couldn't be read
// and no list was cached). force asks the API again (Check now).
func (s *Server) pickRelease(ctx context.Context, force bool) (string, error) {
	p := s.policy()
	repo, _, api := s.releaseURLs(p)
	channel, _ := s.releaseChannel(p)
	if api == "" {
		return "", nil
	}
	l, err := s.githubLister(api)
	if err != nil {
		return "", err
	}
	started := time.Now()
	rels, lerr := l.Releases(ctx, force)
	r, ok := ghrelease.Pick(rels, channel)
	fields := []log.Field{log.F("repo", repo), log.F("channel", channel), log.F("releases", len(rels)), log.F("force", force), log.F("ms", time.Since(started).Milliseconds())}
	s.github.mu.Lock()
	defer s.github.mu.Unlock()
	switch {
	case ok:
		if lerr != nil {
			s.o.Logger.Warn("osadmin: the GitHub releases list wasn't read again; using the last one", append(fields, log.F("tag", r.TagName), log.F("error", lerr.Error()))...)
		} else {
			s.o.Logger.Info("osadmin: GitHub release picked", append(fields, log.F("tag", r.TagName))...)
		}
		s.github.tag = r.TagName
		return r.TagName, nil
	case lerr != nil:
		s.o.Logger.Warn("osadmin: the GitHub releases list can't be read; fetching from the latest stable release", append(fields, log.F("error", lerr.Error()))...)
		s.github.tag = ""
		return "", nil
	}
	s.o.Logger.Warn("osadmin: the repository has no release on the box's channel", fields...)
	return "", codes.New(codes.UpgradeUpload, "%s has no %s release yet", repo, channel)
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
	sigSrc := src
	sigSrc.url += indexSigSuffix
	resp, _, err := s.open(ctx, sigSrc, "index signature")
	if err != nil {
		return updatepkg.Index{}, codes.New(codes.UpgradeSignature, "the index on %s has no signature (%s); the box takes a signed index only", src.base, describe(err))
	}
	sig, err := io.ReadAll(io.LimitReader(resp.Body, maxIndexSig))
	_ = resp.Body.Close()
	if err != nil {
		return updatepkg.Index{}, codes.New(codes.UpgradeUpload, "the index signature can't be read: %v", err)
	}
	key, err := sigbundle.ParsePublicKey(s.o.Upgrade.ReleaseKeyPEM)
	if err != nil {
		return updatepkg.Index{}, codes.Wrap(codes.KitPinMissing, err)
	}
	bd, err := sigbundle.Parse(sig)
	if err == nil {
		err = bd.Verify(key, sha256.Sum256(b))
	}
	if err != nil {
		s.o.Logger.Warn("osadmin: the GitHub index isn't signed by this box's release key; refused", log.F("url", src.url), log.F("error", err.Error()))
		return updatepkg.Index{}, codes.New(codes.UpgradeSignature, "the index on %s isn't signed by this box's release key: %v", src.base, err)
	}
	s.o.Logger.Info("osadmin: the GitHub index's signature verified", log.F("url", src.url), log.F("bytes", len(b)))
	return updatepkg.ReadIndex(bytes.NewReader(b))
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
