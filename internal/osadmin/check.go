// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Check now, the policy's source and a fetch's progress (spec 7, Section
// 2.1). The source is the built-in list compiled into the signed root
// (production: the release download location; lab: the lab mirror the
// build names), a manual URL, or none, which leaves upload only. The
// index is read again on every Check now, and each unit's offers come
// from it; nothing in it is trusted, since every .bin is verified when
// it's staged.
package osadmin

import (
	"bufio"
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/ghrelease"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/webslots"
)

// The policy's sources.
const (
	SourceBuiltIn = "builtin"
	SourceManual  = "manual"
	SourceNone    = "none"
)

// DefaultPatchMinFree is the free memory below which a box prefers a full
// .bin to a patch: rebuilding one holds the base root image in memory.
const DefaultPatchMinFree = 600 << 20

// effectiveSource is the policy's source, filled in for a policy from
// before it: a mirror URL is the manual source, direct alone the built-in
// list, neither none.
func effectiveSource(p Policy, directAvailable bool) string {
	switch p.Source {
	case SourceBuiltIn, SourceManual, SourceNone:
		return p.Source
	}
	switch {
	case p.MirrorURL != "":
		return SourceManual
	case p.Direct && directAvailable:
		return SourceBuiltIn
	}
	return SourceNone
}

// builtinList is the built-in source list: the lab mirrors the build
// names, then the release source; a lab build's GitHub repository
// override alone when it's set.
func (s *Server) builtinList() []string {
	p := s.policy()
	_, web, _ := s.releaseURLs(p)
	if s.labOverride(p) {
		return []string{web}
	}
	out := append([]string(nil), s.o.Upgrade.BuiltinMirrors...)
	if web != "" {
		out = append(out, web)
	}
	return out
}

// checks holds the last Check now and the last fetch, in memory.
type checks struct {
	mu    sync.Mutex
	last  *osadminv1.CheckUpdatesResponse
	fetch *osadminv1.FetchProgress
}

func (s *Server) lastCheck() *osadminv1.CheckUpdatesResponse {
	s.checks.mu.Lock()
	defer s.checks.mu.Unlock()
	if s.checks.last == nil {
		return nil
	}
	return proto.CloneOf(s.checks.last)
}

func (s *Server) fetchProgress() *osadminv1.FetchProgress {
	s.checks.mu.Lock()
	defer s.checks.mu.Unlock()
	if s.checks.fetch == nil {
		return nil
	}
	return proto.CloneOf(s.checks.fetch)
}

// fetchTarget is the unit a file's name says.
func fetchTarget(name string) osadminv1.UpdateTarget {
	switch {
	case strings.HasPrefix(name, updatepkg.NameProduct+"-"):
		return osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT
	case strings.HasPrefix(name, updatepkg.Name+"-baseWeb-"):
		return osadminv1.UpdateTarget_UPDATE_TARGET_BASE_WEB
	}
	return osadminv1.UpdateTarget_UPDATE_TARGET_BASE
}

// beginFetch starts a fetch's progress record.
func (s *Server) beginFetch(name, from string) {
	now := timestamppb.New(s.o.Clock.Now())
	s.checks.mu.Lock()
	defer s.checks.mu.Unlock()
	s.checks.fetch = &osadminv1.FetchProgress{FileName: name, Target: fetchTarget(name), State: "querying", Source: from, StartedAt: now, UpdatedAt: now}
}

func (s *Server) fetchState(f func(p *osadminv1.FetchProgress)) {
	s.checks.mu.Lock()
	defer s.checks.mu.Unlock()
	if s.checks.fetch == nil {
		return
	}
	f(s.checks.fetch)
	s.checks.fetch.UpdatedAt = timestamppb.New(s.o.Clock.Now())
}

// progressReader counts a download into the fetch's progress: bytes,
// speed since it started and what's left at that speed.
type progressReader struct {
	r       io.Reader
	s       *Server
	total   int64
	done    int64
	started time.Time
	last    time.Time
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.done += int64(n)
	now := time.Now()
	if now.Sub(p.last) >= 200*time.Millisecond || err != nil {
		p.last = now
		done, total := p.done, p.total
		elapsed := now.Sub(p.started).Seconds()
		p.s.fetchState(func(f *osadminv1.FetchProgress) {
			f.DoneBytes, f.TotalBytes = done, max(total, 0)
			if elapsed > 0 {
				f.BytesPerSecond = int64(float64(done) / elapsed)
			}
			if f.BytesPerSecond > 0 && total > done {
				f.EtaSeconds = (total - done) / f.BytesPerSecond
			} else {
				f.EtaSeconds = 0
			}
		})
	}
	return n, err
}

// verifyFetched checks a fetched file's signature, channel and SHA-256 as
// a stage will, for the fetch's progress. A file that fails stays held:
// Verify and stage refuses and removes it, or Cancel drops it.
func (s *Server) verifyFetched(id string) {
	s.fetchState(func(f *osadminv1.FetchProgress) { f.State, f.UploadId = "verifying", id })
	err := func() error {
		path, err := s.uploadPath(id)
		if err != nil {
			return err
		}
		f, err := os.Open(path) // #nosec G304 -- an upload this box made
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		p, err := updatepkg.Read(f, st.Size())
		if err != nil {
			return err
		}
		return p.Verify(s.o.Upgrade.ReleaseKeyPEM, s.o.Upgrade.Channel)
	}()
	s.fetchState(func(f *osadminv1.FetchProgress) {
		f.State, f.Verified = "done", err == nil
		if err != nil {
			f.Error, f.Code = describe(err), symbolOf(err)
		}
	})
	if err != nil {
		s.o.Logger.Warn("osadmin: a fetched file doesn't verify; Verify and stage will refuse it", log.F("upload", id), log.F("error", describe(err)))
	}
}

// memAvailable is the box's free memory (MemAvailable), or -1 when it
// can't be read.
func (s *Server) memAvailable() int64 {
	if f := s.o.Upgrade.MemAvailable; f != nil {
		return f()
	}
	fh, err := os.Open("/proc/meminfo")
	if err != nil {
		return -1
	}
	defer func() { _ = fh.Close() }()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) >= 2 && f[0] == "MemAvailable:" {
			if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				return kb << 10
			}
		}
	}
	return -1
}

func (s *Server) patchMinFree() int64 {
	if s.o.Upgrade.PatchMinFree > 0 {
		return s.o.Upgrade.PatchMinFree
	}
	return DefaultPatchMinFree
}

// box is what this box runs, for the units' offers.
func (s *Server) box(base string) updatepkg.Box {
	ch, _ := s.releaseChannel(s.policy())
	return updatepkg.Box{Arch: s.arch(), Channel: s.o.Upgrade.Channel, Epoch: updatepkg.BoxEpoch, BaseOS: base, BaseWeb: s.webServed().Version, Prerelease: ch == ghrelease.RC}
}

// CheckUpdates reads the index again and answers each unit's offers.
func (h *upgradeSvc) CheckUpdates(ctx context.Context, _ *connect.Request[osadminv1.CheckUpdatesRequest]) (*connect.Response[osadminv1.CheckUpdatesResponse], error) {
	s := h.s
	srcs := s.sources(updatepkg.IndexName)
	if len(srcs) == 0 {
		return nil, codes.New(codes.UpgradeAirGapped, "the box has no update source (upload only); choose the built-in list or a mirror, or upload the .bin")
	}
	base, err := s.baseVersion(ctx)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, src := range srcs {
		idx, err := s.fetchIndex(ctx, src, true)
		if err != nil {
			lastErr = err
			continue
		}
		out := s.offers(idx, base)
		out.Source, out.Url, out.CheckedAt = src.name, src.base, timestamppb.New(s.o.Clock.Now())
		s.checks.mu.Lock()
		s.checks.last = proto.CloneOf(out)
		s.checks.mu.Unlock()
		s.o.Logger.Info("osadmin: updates checked", log.F("source", src.name), log.F("format", out.GetIndexFormat()), log.F("baseOS", len(out.GetBaseOs())), log.F("baseWeb", len(out.GetBaseWeb())), log.F("product", len(out.GetProduct())))
		return connect.NewResponse(out), nil
	}
	return nil, lastErr
}

// offers is each unit's offers from idx for a box running base.
func (s *Server) offers(idx updatepkg.Index, base string) *osadminv1.CheckUpdatesResponse {
	b := s.box(base)
	out := &osadminv1.CheckUpdatesResponse{IndexFormat: int32(min(idx.Format, 1<<20))} // #nosec G115 -- clamped
	inst, hasProduct := s.slots().Installed()
	web, hasWeb := s.webSlots().Header("current")
	roomForPatch := s.memAvailable() < 0 || s.memAvailable() >= s.patchMinFree()
	preferred := ""
	for _, e := range idx.OfferBaseOS(b) {
		o := &osadminv1.UnitOffer{Target: osadminv1.UpdateTarget_UPDATE_TARGET_BASE, Version: e.Version, Kind: e.Kind, FileName: e.File, Size: e.Size, Bases: e.Bases, Commit: e.Commit,
			IncludesBaseWeb: e.Includes[updatepkg.UnitBaseWeb]}
		if hasProduct && inst.HasRange() && !inst.InRange(e.Version) {
			o.OutsideProductRange, o.ProductRange = true, inst.RangeText()
		}
		if hasWeb {
			o.Note = webAfterBaseOS(web, e.Version, o.GetIncludesBaseWeb())
		}
		if preferred == "" && (e.Kind == string(updatepkg.KindFull) || roomForPatch) {
			o.Preferred, preferred = true, e.Version
		}
		out.BaseOs = append(out.BaseOs, o)
	}
	for i, e := range idx.OfferBaseWeb(b) {
		need := updatepkg.DefaultRange(e.Version, e.Channel)
		if r, ok := e.Requires[updatepkg.UnitBaseOS]; ok {
			need = r
		}
		out.BaseWeb = append(out.BaseWeb, &osadminv1.UnitOffer{Target: osadminv1.UpdateTarget_UPDATE_TARGET_BASE_WEB, Version: e.Version, Kind: e.Kind, FileName: e.File, Size: e.Size, Commit: e.Commit, Needs: need.Text(), Preferred: i == 0})
	}
	if e, need, ok := idx.UnfitBaseWeb(b); ok {
		out.BaseWebWaits = "Base Web " + e.Version + " needs Base OS " + need.Text() + "."
	}
	installed := s.slots().Status().Installed
	for i, e := range idx.OfferProducts(b, installed) {
		h := updatepkg.Header{MinBase: e.MinBase, MaxBase: e.MaxBase}
		needs := ""
		if h.HasRange() {
			needs = h.RangeText()
		}
		out.Product = append(out.Product, &osadminv1.UnitOffer{Target: osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT, Version: e.Version, Kind: "full", FileName: e.File, Size: e.Size, Bases: e.Bases, Needs: needs, Preferred: i == 0})
	}
	return out
}

// webAfterBaseOS says what :8443 serves after a Base OS update to version,
// which ships with Base Web includes ("" for a release from before the
// rule), when the Base Web web is installed: the built-in pages of the
// new Base OS when web doesn't fit it, or when the release's own Base Web
// is newer than web (the box never serves an older Base Web than its own
// pages); "" when web keeps serving.
func webAfterBaseOS(web updatepkg.Header, version, includes string) string {
	if need, _ := web.NeedsBaseOS(); !need.Contains(version) {
		return "After the reboot the box serves the built-in pages of " + version + " until a Base Web that fits it is installed (the installed Base Web " + web.Version + " needs Base OS " + need.Text() + ")."
	}
	if includes != "" && webslots.Newer(includes, web.Version) {
		return "After the reboot the box serves Base Web " + includes + ", which this release includes, in place of the installed Base Web " + web.Version + "."
	}
	return ""
}

// baseOSNote is GetUpgrades' note on a staged Base OS, which ships with
// Base Web includes, when the installed Base Web won't serve after it.
func (s *Server) baseOSNote(staged, includes string) string {
	if staged == "" {
		return ""
	}
	web, ok := s.webSlots().Header("current")
	if !ok {
		return ""
	}
	return webAfterBaseOS(web, staged, includes)
}
