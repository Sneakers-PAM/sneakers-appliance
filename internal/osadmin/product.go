// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// The product bundle on the Updates page. It goes through the same flow as
// a base update: fetch or upload, stage (verified before anything is
// unpacked), apply and revert, the update window, the history and the
// maintenance gate. Only the slots differ: the product's are on the state
// volume (internal/product), and an apply or revert restarts the product
// services instead of rebooting. The first install is a stage and an apply
// with no previous slot.
package osadmin

import (
	"context"
	"errors"
	"strings"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/product"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productinfo"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

// ProductService is the service table entry the product runs as.
const ProductService = "k0s"

// ProductPorts are the ports the product serves on the service interface
// (the management one when the box has only one), opened once a product
// bundle is installed: 443, and 80, which redirects to it.
var ProductPorts = []uint32{80, 443}

// source is one place the box fetches from: its name (mirror, builtin or
// direct), the file's URL, and the base URL it's under.
type source struct{ name, url, base string }

// sources lists, in order, where file is fetched from (spec 7, Section
// 2.1): with the built-in source, each entry of the built-in list (a flat
// mirror, or the release source's tag path); with the manual source, the
// mirror URL; with none, nothing. A policy from before the source keeps
// its order: the mirror, then the release source when direct is on.
// direct is the path under the release source (the index's or the
// file's).
func (s *Server) sources(file, direct string) []source {
	p := s.policy()
	var out []source
	switch p.Source {
	case SourceBuiltIn:
		for _, u := range s.o.Upgrade.BuiltinMirrors {
			b := strings.TrimRight(u, "/")
			out = append(out, source{SourceBuiltIn, b + "/" + file, b})
		}
		if d := s.o.Upgrade.DirectURL; d != "" {
			out = append(out, source{"direct", d + "/" + direct, d})
		}
		return out
	case SourceManual:
		if p.MirrorURL != "" {
			out = append(out, source{"mirror", p.MirrorURL + "/" + file, p.MirrorURL})
		}
		return out
	case SourceNone:
		return nil
	}
	if p.MirrorURL != "" {
		out = append(out, source{"mirror", p.MirrorURL + "/" + file, p.MirrorURL})
	}
	if d := s.o.Upgrade.DirectURL; p.Direct && d != "" {
		out = append(out, source{"direct", d + "/" + direct, d})
	}
	return out
}

// directPath is where the release source keeps a .bin: the tag's assets.
func directPath(file string) string {
	v, ok := updatepkg.ReleaseOf(file)
	if !ok {
		return ""
	}
	return "download/v" + v + "/" + file
}

func (s *Server) slots() product.Slots {
	if s.o.Upgrade.ProductDir != "" {
		return product.Slots{Dir: s.o.Upgrade.ProductDir}
	}
	return product.Slots{Dir: product.Dir}
}

func (s *Server) arch() string {
	if s.o.Upgrade.Arch != "" {
		return s.o.Upgrade.Arch
	}
	return "amd64"
}

func (s *Server) baseVersion(ctx context.Context) (string, error) {
	st, err := s.o.Image.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{}))
	if err != nil {
		return "", err
	}
	return st.Msg.GetRunningVersion(), nil
}

// productSlots is GetUpgrades' view of the product.
func (s *Server) productSlots(ctx context.Context) *osadminv1.ProductSlots {
	sl := s.slots()
	st := sl.Status()
	out := &osadminv1.ProductSlots{InstalledVersion: st.Installed, StagedVersion: st.Staged, PreviousVersion: st.Previous,
		Name: productinfo.Installed(sl.Dir).Title, Fits: true}
	if inst, ok := sl.Installed(); ok && inst.HasRange() {
		out.RequiresBaseOs = inst.RangeText()
		if base, err := s.baseVersion(ctx); err == nil {
			out.Fits = inst.InRange(base)
		}
	}
	if s.o.Services != nil {
		if r, err := s.o.Services.Status(ctx, connect.NewRequest(&initv1.StatusRequest{Name: ProductService})); err == nil {
			out.Running = r.Msg.GetRunning()
		}
	}
	return out
}

// ListProductVersions reads the index from the mirror, then the release
// source, and offers what fits this box.
func (h *upgradeSvc) ListProductVersions(ctx context.Context, _ *connect.Request[osadminv1.ListProductVersionsRequest]) (*connect.Response[osadminv1.ListProductVersionsResponse], error) {
	s := h.s
	srcs := s.sources(updatepkg.IndexName, "latest/download/"+updatepkg.IndexName)
	if len(srcs) == 0 {
		return nil, codes.New(codes.UpgradeAirGapped, "no mirror is configured and direct fetches are off, so this box never fetches; upload the product bundle instead")
	}
	base, err := s.baseVersion(ctx)
	if err != nil {
		return nil, err
	}
	installed := s.slots().Status().Installed
	var lastErr error
	for _, src := range srcs {
		idx, err := s.fetchIndex(ctx, src)
		if err != nil {
			lastErr = err
			continue
		}
		out := &osadminv1.ListProductVersionsResponse{BaseVersion: base}
		for _, e := range idx.Offer(s.arch(), s.o.Upgrade.Channel, base, installed) {
			out.Versions = append(out.Versions, &osadminv1.ProductVersion{Version: e.Version, Arch: e.Arch, Channel: e.Channel, Bases: e.Bases, FileName: e.File, Size: e.Size, Source: src.name, MinBase: e.MinBase, MaxBase: e.MaxBase})
		}
		s.o.Logger.Info("osadmin: product versions listed", log.F("source", src.name), log.F("base", base), log.F("installed", installed), log.F("offered", len(out.Versions)))
		return connect.NewResponse(out), nil
	}
	return nil, lastErr
}

// ListBaseVersions reads the same index, from the mirror, then the
// release source, and offers the base releases in its base section that
// fit this box, marking those outside the installed product's base range.
func (h *upgradeSvc) ListBaseVersions(ctx context.Context, _ *connect.Request[osadminv1.ListBaseVersionsRequest]) (*connect.Response[osadminv1.ListBaseVersionsResponse], error) {
	s := h.s
	srcs := s.sources(updatepkg.IndexName, "latest/download/"+updatepkg.IndexName)
	if len(srcs) == 0 {
		return nil, codes.New(codes.UpgradeAirGapped, "no mirror is configured and direct fetches are off, so this box never fetches; upload the base release instead")
	}
	base, err := s.baseVersion(ctx)
	if err != nil {
		return nil, err
	}
	inst, hasProduct := s.slots().Installed()
	var lastErr error
	for _, src := range srcs {
		idx, err := s.fetchIndex(ctx, src)
		if err != nil {
			lastErr = err
			continue
		}
		out := &osadminv1.ListBaseVersionsResponse{BaseVersion: base}
		for _, e := range idx.OfferBaseOS(s.box(base)) {
			v := &osadminv1.BaseVersion{Version: e.Version, Arch: e.Arch, Channel: e.Channel, Kind: e.Kind, Bases: e.Bases, FileName: e.File, Size: e.Size, Source: src.name}
			if hasProduct && inst.HasRange() && !inst.InRange(e.Version) {
				v.OutsideProductRange, v.ProductRange = true, inst.RangeText()
			}
			out.Versions = append(out.Versions, v)
		}
		s.o.Logger.Info("osadmin: base versions listed", log.F("source", src.name), log.F("base", base), log.F("offered", len(out.Versions)))
		return connect.NewResponse(out), nil
	}
	return nil, lastErr
}

func (s *Server) fetchIndex(ctx context.Context, src source) (idx updatepkg.Index, err error) {
	started := time.Now()
	resp, peer, err := s.open(ctx, src, "product index")
	if err == nil {
		idx, err = updatepkg.ReadIndex(resp.Body)
		_ = resp.Body.Close()
	}
	s.fetched(ctx, src, "product index", peer, started, 0, err)
	return idx, err
}

// stageProduct stages a verified product bundle: it must fit the running
// base (refused, and the upload removed, before anything is decrypted),
// then it's decrypted and unpacked into the free product slot and checked
// there. The upload is removed once it's staged.
func (s *Server) stageProduct(ctx context.Context, path string, p *updatepkg.Package) error {
	base, err := s.baseVersion(ctx)
	if err != nil {
		return err
	}
	if err := p.Header.AppliesTo(base); err != nil {
		s.reject(path, err)
		return err
	}
	if !p.Header.HasRange() {
		s.o.Logger.Info("osadmin: the product bundle names exact bases, not a base range; accepted as sealed before the range existed", log.F("version", p.Header.Version), log.F("bases", strings.Join(p.Header.Bases, ",")))
	}
	key, err := sigbundle.ParsePublicKey(s.o.Upgrade.ReleaseKeyPEM)
	if err != nil {
		return codes.Wrap(codes.KitPinMissing, err)
	}
	s.o.Logger.Info("osadmin: product bundle verified; unpacking", log.F("version", p.Header.Version), log.F("base", base))
	s.setStep(stepStage, "Decrypting, unpacking and checking the bundle.")
	id, err := s.o.Upgrade.UpdateKey()
	if err != nil {
		return codes.Wrap(codes.UpgradeDecrypt, err)
	}
	if err := s.slots().Stage(p.Header, func(dir string) error { return unpack(p, id, dir) }, key); err != nil {
		s.o.Logger.Warn("osadmin: product bundle not staged", log.F("version", p.Header.Version), log.F("error", describe(err)))
		return err
	}
	s.removeUpload(path)
	s.o.Logger.Info("osadmin: product bundle staged", log.F("version", p.Header.Version))
	return nil
}

// applyProduct switches to the staged product slot and restarts the
// product, under the same maintenance gate as a base apply.
func (s *Server) applyProduct(ctx context.Context, by osaudit.Entry, o *osadminv1.ElevationOverride) (string, string, error) {
	v := s.slots().Status().Staged
	var err error
	if v == "" {
		err = codes.New(codes.UpgradeNotStaged, "no product bundle is staged; upload or fetch one and stage it first")
	}
	overrode := ""
	if err == nil {
		overrode, err = s.beginMaintenance(ctx, "product update applies", by, o)
		if err == nil {
			s.continueApply(osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT, v, "")
			err = s.switchProduct(ctx, func() error { _, err := s.slots().Apply(); return err })
			s.endMaintenance()
		}
	}
	s.historyFor(osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT, "apply", v, by.Actor, err, overrideDetail(overrode))
	s.o.Logger.Info("osadmin: product apply", log.F("version", v), log.F("by", by.Actor), log.F("ok", err == nil))
	return v, overrode, err
}

// revertProduct goes back to the previous product slot.
func (s *Server) revertProduct(ctx context.Context, by osaudit.Entry, o *osadminv1.ElevationOverride) (string, string, error) {
	overrode, err := s.beginMaintenance(ctx, "product update reverts", by, o)
	v := ""
	if err == nil {
		s.beginProgress("revert", osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT, s.slots().Status().Previous, "")
		err = s.switchProduct(ctx, func() error {
			var err error
			v, err = s.slots().Revert()
			return err
		})
		s.endMaintenance()
	}
	s.historyFor(osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT, "revert", v, by.Actor, err, overrideDetail(overrode))
	s.o.Logger.Info("osadmin: product revert", log.F("version", v), log.F("by", by.Actor), log.F("ok", err == nil))
	return v, overrode, err
}

// switchProduct runs a product apply's or revert's switch, then the
// product's restart, each as its step.
func (s *Server) switchProduct(ctx context.Context, switchSlots func() error) error {
	s.setStep(stepSwitch, "")
	if err := switchSlots(); err != nil {
		s.failStep(stepSwitch, err)
		return err
	}
	s.setStep(stepRestart, "")
	if err := s.restartProduct(ctx); err != nil {
		s.failStep(stepRestart, err)
		return err
	}
	s.finishSteps(stepRestart)
	if s.o.ProductUp != nil {
		s.startProductUp()
	}
	return nil
}

// restartProduct stops the product service and starts it from the current
// slot, then opens the product's ports.
func (s *Server) restartProduct(ctx context.Context) error {
	if s.o.Services == nil {
		return errors.New("osadmin: no services client; the product can't be restarted")
	}
	started := time.Now()
	if _, err := s.o.Services.Stop(ctx, connect.NewRequest(&initv1.StopRequest{Name: ProductService})); err != nil {
		return err
	}
	if _, err := s.o.Services.Start(ctx, connect.NewRequest(&initv1.StartRequest{Name: ProductService})); err != nil {
		return err
	}
	s.o.Logger.Info("osadmin: product restarted", log.F("service", ProductService), log.F("ms", time.Since(started).Milliseconds()))
	return s.OpenProductPorts(ctx)
}

// OpenProductPorts opens 80 and 443 on the service interface when a product
// bundle is installed; netd keeps them only while it runs, so accessd
// calls this when it starts too.
func (s *Server) OpenProductPorts(ctx context.Context) error {
	if s.slots().Status().Installed == "" || s.o.Network == nil {
		return nil
	}
	var rules []*netdv1.PortRule
	for _, p := range ProductPorts {
		rules = append(rules, &netdv1.PortRule{Protocol: "tcp", Port: p})
	}
	if _, err := s.o.Network.SetServicePorts(ctx, connect.NewRequest(&netdv1.SetServicePortsRequest{Rules: rules})); err != nil {
		s.o.Logger.Error(err, "osadmin: the product's ports weren't opened")
		return err
	}
	s.o.Logger.Info("osadmin: product ports open", log.F("ports", "80,443"))
	return nil
}
