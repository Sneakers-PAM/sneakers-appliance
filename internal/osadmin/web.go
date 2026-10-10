// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// The Base Web unit on the Updates page (spec 7): the :8443 pages in the
// web slots on the state volume (internal/webslots). accessd stages,
// applies and reverts by moving the slots' links; sneakers-osadmin, which
// serves the pages, loads the current slot with its checks and swaps what
// it serves in one step, and records what it serves in a status file. An
// apply or revert waits for that record and puts the links back when the
// pages didn't take. Nothing else moves: no reboot, no maintenance, and
// the root slots, the product, the sessions and elevation are left alone.
package osadmin

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/webslots"
)

// WebServedFile is the status sneakers-osadmin writes, in its own
// directory (Paths.OwnDir), of the pages it serves.
const WebServedFile = "web-served.json"

// DefaultWebSwitchWait is how long a Base Web apply or revert waits for
// sneakers-osadmin to serve the pages it switched to.
const DefaultWebSwitchWait = 20 * time.Second

// stepLoad is a Base Web apply's or revert's last step: sneakers-osadmin
// loads and checks the pages and serves them.
const stepLoad = "load"

func (s *Server) webSlots() webslots.Slots {
	if s.o.Upgrade.WebDir != "" {
		return webslots.Slots{Dir: s.o.Upgrade.WebDir}
	}
	return webslots.Slots{Dir: webslots.Dir}
}

// builtinWebVersion is the version of the pages the running root carries.
func (s *Server) builtinWebVersion() string {
	if s.o.Upgrade.BuiltinWebVersion != "" {
		return s.o.Upgrade.BuiltinWebVersion
	}
	return release.Version
}

// webServed is what sneakers-osadmin serves, from its status file; with
// none, the built-in pages.
func (s *Server) webServed() webslots.Served {
	if f := s.o.Upgrade.WebServedFile; f != "" {
		if sv, err := webslots.ReadServed(f); err == nil {
			return sv
		}
	}
	return webslots.Served{Version: s.builtinWebVersion(), Source: webslots.SourceBuiltIn}
}

// baseWebStatus is GetUpgrades' view of the Base Web.
func (s *Server) baseWebStatus(ctx context.Context) *osadminv1.BaseWebStatus {
	sv := s.webServed()
	st := s.webSlots().Status()
	out := &osadminv1.BaseWebStatus{RunningVersion: sv.Version, Source: sv.Source, Slot: sv.Slot, Reason: sv.Reason, CurrentVersion: st.Current, StagedVersion: st.Staged,
		PreviousVersion: st.Previous, CanRevert: st.Current != "", BuiltinVersion: s.builtinWebVersion(), Fits: true}
	if h, ok := s.webSlots().Header("current"); ok {
		need, _ := h.NeedsBaseOS()
		out.RequiresBaseOs = need.Text()
		if base, err := s.baseVersion(ctx); err == nil {
			out.Fits = need.Contains(base)
		}
	}
	return out
}

// stageWeb stages a verified Base Web package: it must fit the running
// Base OS (UPGRADE_COMPAT, and the upload is kept so it can be staged
// once the Base OS fits) and be newer than the pages served now
// (UPGRADE_DOWNGRADE); then it's decrypted and unpacked into the free web
// slot and loaded there with every check.
func (s *Server) stageWeb(ctx context.Context, path string, p *updatepkg.Package) error {
	base, err := s.baseVersion(ctx)
	if err != nil {
		return err
	}
	if err := updatepkg.FitsBaseOS(p.Header, base, ""); err != nil {
		s.o.Logger.Warn("osadmin: a Base Web doesn't fit the running Base OS; the upload is kept", log.F("version", p.Header.Version), log.F("base", base), log.F("error", describe(err)))
		return err
	}
	if served := s.webServed().Version; !webslots.Newer(p.Header.Version, served) {
		return codes.New(codes.UpgradeDowngrade, "Base Web %s isn't newer than the %s pages served now", p.Header.Version, served)
	}
	key, err := sigbundle.ParsePublicKey(s.o.Upgrade.ReleaseKeyPEM)
	if err != nil {
		return codes.Wrap(codes.KitPinMissing, err)
	}
	s.setStep(stepStage, "Decrypting, unpacking and checking the pages.")
	id, err := s.o.Upgrade.UpdateKey()
	if err != nil {
		return codes.Wrap(codes.UpgradeDecrypt, err)
	}
	if err := s.webSlots().Stage(p.Header, func(dir string) error { return unpack(p, id, dir) }, key); err != nil {
		s.o.Logger.Warn("osadmin: Base Web not staged", log.F("version", p.Header.Version), log.F("error", describe(err)))
		return err
	}
	s.removeUpload(path)
	s.o.Logger.Info("osadmin: Base Web staged", log.F("version", p.Header.Version), log.F("slot", s.webSlots().Status().StagedSlot))
	return nil
}

// applyWeb switches :8443 to the staged pages.
func (s *Server) applyWeb(ctx context.Context, by osaudit.Entry) (string, error) {
	sl := s.webSlots()
	h, ok := sl.Header("staged")
	var err error
	if !ok {
		err = codes.New(codes.UpgradeNotStaged, "no Base Web is staged; upload or fetch one and stage it first")
	}
	if err == nil {
		base, berr := s.baseVersion(ctx)
		if err = berr; err == nil {
			err = updatepkg.FitsBaseOS(h, base, "")
		}
	}
	if err == nil {
		slot := sl.Status().StagedSlot
		s.continueApply(osadminv1.UpdateTarget_UPDATE_TARGET_BASE_WEB, h.Version, slot)
		err = s.switchWeb(ctx, h.Version, slot, sl.Apply)
	}
	s.historyFor(osadminv1.UpdateTarget_UPDATE_TARGET_BASE_WEB, "apply", h.Version, by.Actor, err, "")
	s.o.Logger.Info("osadmin: Base Web apply", log.F("version", h.Version), log.F("by", by.Actor), log.F("ok", err == nil))
	return h.Version, err
}

// revertWeb goes back to the previous web slot, or with none (or one
// older than the root's own pages) to the built-in pages. A previous Base Web that doesn't fit the running Base
// OS is refused (UPGRADE_COMPAT).
func (s *Server) revertWeb(ctx context.Context, by osaudit.Entry) (string, error) {
	sl := s.webSlots()
	st := sl.Status()
	back, slot := st.Previous, st.PreviousSlot
	if back == "" {
		back = s.builtinWebVersion()
	}
	var err error
	if st.Current == "" {
		err = codes.New(codes.UpgradeNoPrevious, "the box serves its built-in pages; there's no Base Web to revert")
	}
	if h, ok := sl.Header("previous"); ok && err == nil {
		base, berr := s.baseVersion(ctx)
		if err = berr; err == nil {
			err = updatepkg.FitsBaseOS(h, base, "")
		}
	}
	if slot != "" && webslots.Newer(s.builtinWebVersion(), back) {
		// The watcher never serves a Base Web older than the root's own
		// pages, so the revert ends on those.
		back, slot = s.builtinWebVersion(), ""
	}
	if err == nil {
		s.beginProgress("revert", osadminv1.UpdateTarget_UPDATE_TARGET_BASE_WEB, back, slot)
		err = s.switchWeb(ctx, back, slot, sl.Revert)
	}
	s.historyFor(osadminv1.UpdateTarget_UPDATE_TARGET_BASE_WEB, "revert", back, by.Actor, err, "")
	s.o.Logger.Info("osadmin: Base Web revert", log.F("version", back), log.F("by", by.Actor), log.F("ok", err == nil))
	return back, err
}

// switchWeb moves the links, then waits until sneakers-osadmin serves
// version from slot ("" for the built-in pages); when it doesn't, the
// links go back and the step fails (UPGRADE_WEB_LOAD), and the pages
// served before keep serving.
func (s *Server) switchWeb(ctx context.Context, version, slot string, move func() (string, func() error, error)) error {
	s.setStep(stepSwitch, "")
	_, undo, err := move()
	if err != nil {
		s.failStep(stepSwitch, err)
		return err
	}
	s.setStep(stepLoad, "Waiting for :8443 to load and check the pages.")
	if err := s.waitServed(ctx, version, slot); err != nil {
		if uerr := undo(); uerr != nil {
			s.o.Logger.Error(uerr, "osadmin: the web slots' links weren't put back")
		}
		s.failStep(stepLoad, err)
		return err
	}
	s.finishSteps(stepLoad)
	return nil
}

// waitServed waits for the status file to show version served from slot,
// or the built-in pages when slot is "".
func (s *Server) waitServed(ctx context.Context, version, slot string) error {
	if s.o.Upgrade.WebServedFile == "" {
		s.o.Logger.Warn("osadmin: no served-pages status to wait for; the switch isn't confirmed")
		return nil
	}
	wait := s.o.Upgrade.WebSwitchWait
	if wait <= 0 {
		wait = DefaultWebSwitchWait
	}
	deadline := time.Now().Add(wait)
	for {
		sv := s.webServed()
		switch {
		case slot == "" && sv.Source == webslots.SourceBuiltIn:
			return nil
		case slot != "" && sv.Source == webslots.SourceSlot && sv.Slot == slot && sv.Version == version:
			return nil
		case slot != "" && sv.WantedSlot == slot && sv.WantedVersion == version && sv.Reason != "":
			return codes.New(codes.UpgradeWebLoad, ":8443 didn't take Base Web %s: %s; the pages served before keep serving", version, sv.Reason)
		}
		if time.Now().After(deadline) {
			return codes.New(codes.UpgradeWebLoad, ":8443 didn't serve Base Web %s within %s; the pages served before keep serving", version, wait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// freeWebSlot is the web slot a stage fills: the one current doesn't name.
func (s *Server) freeWebSlot() string {
	if s.webSlots().Status().CurrentSlot == "a" {
		return "b"
	}
	return "a"
}
