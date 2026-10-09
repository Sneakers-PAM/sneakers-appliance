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
	"net/http"
	"os"
	"regexp"
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

var fileVersionRE = regexp.MustCompile(`^sneakers-(?:appliance|product)-([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)-(?:amd64|arm64)(?:-LAB)?\.bin$`)

// source is one place the box fetches from.
type source struct{ name, url string }

// sources lists, in order, where file is fetched from: the mirror, then
// the release source when the policy allows direct fetches. direct is the
// path under the release source (the index's or the file's).
func (s *Server) sources(file, direct string) []source {
	p := s.policy()
	var out []source
	if p.MirrorURL != "" {
		out = append(out, source{"mirror", p.MirrorURL + "/" + file})
	}
	if p.Direct && s.o.Upgrade.DirectURL != "" {
		out = append(out, source{"direct", s.o.Upgrade.DirectURL + "/" + direct})
	}
	return out
}

// directPath is where the release source keeps a .bin: the tag's assets.
func directPath(file string) string {
	m := fileVersionRE.FindStringSubmatch(file)
	if m == nil {
		return ""
	}
	return "download/v" + m[1] + "/" + file
}

func (s *Server) httpClient() *http.Client {
	if hc := s.o.Upgrade.HTTPClient; hc != nil {
		return hc
	}
	return &http.Client{Timeout: time.Hour, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
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
		Name: productinfo.Installed(sl.Dir).Title}
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
		idx, err := s.fetchIndex(ctx, src.url)
		if err != nil {
			lastErr = err
			continue
		}
		out := &osadminv1.ListProductVersionsResponse{BaseVersion: base}
		for _, e := range idx.Offer(s.arch(), s.o.Upgrade.Channel, base, installed) {
			out.Versions = append(out.Versions, &osadminv1.ProductVersion{Version: e.Version, Arch: e.Arch, Channel: e.Channel, Bases: e.Bases, FileName: e.File, Size: e.Size, Source: src.name})
		}
		s.o.Logger.Info("osadmin: product versions listed", log.F("source", src.name), log.F("base", base), log.F("installed", installed), log.F("offered", len(out.Versions)))
		return connect.NewResponse(out), nil
	}
	return nil, lastErr
}

func (s *Server) fetchIndex(ctx context.Context, target string) (updatepkg.Index, error) {
	started := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return updatepkg.Index{}, codes.Wrap(codes.UpgradeUpload, err)
	}
	resp, err := s.httpClient().Do(req)
	if err != nil {
		s.o.Logger.Warn("osadmin: product index fetch failed", log.F("target", target), log.F("error", err.Error()))
		return updatepkg.Index{}, codes.New(codes.UpgradeUpload, "the product index didn't come: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		s.o.Logger.Warn("osadmin: product index fetch refused", log.F("target", target), log.F("status", resp.Status))
		return updatepkg.Index{}, codes.New(codes.UpgradeUpload, "the product index source answered %s", resp.Status)
	}
	idx, err := updatepkg.ReadIndex(resp.Body)
	s.o.Logger.Info("osadmin: product index fetch", log.F("target", target), log.F("ms", time.Since(started).Milliseconds()), log.F("ok", err == nil))
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
	if err := os.Remove(path); err != nil {
		s.o.Logger.Warn("osadmin: a staged product bundle's upload wasn't removed", log.F("error", err.Error()))
	}
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
