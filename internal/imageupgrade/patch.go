// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package imageupgrade

import (
	"context"
	"fmt"
	"io"
	"path"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/basepatch"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
)

// ActiveSlot is a Slots that also reads the slot the box runs from: the
// base a patch is rebuilt from.
type ActiveSlot interface {
	OpenActive(ctx context.Context) (io.ReaderAt, io.Closer, error)
}

// StagePatch rebuilds a Base OS release in the layout at dir from the
// running release and the patch's deltas there (basepatch), then stages
// it as Stage does, through the whole verify chain. The running root
// image and UKI are checked against the patch's base before anything is
// written (UPGRADE_PATCH_BASE); a rebuild that isn't byte for byte the
// target is UPGRADE_PATCH_RESULT, and nothing is staged.
func (s *Stager) StagePatch(ctx context.Context, dir string, p basepatch.Spec, arch string) (string, error) {
	lg := s.logger()
	active, ok := s.Slots.(ActiveSlot)
	if !ok {
		return "", codes.New(codes.UpgradePatchBase, "this box can't read its running root slot, so it can't apply a patch; take the full .bin")
	}
	uki, err := s.runningUKI()
	if err != nil {
		return "", err
	}
	r, c, err := active.OpenActive(ctx)
	if err != nil {
		return "", codes.New(codes.UpgradePatchBase, "the running root slot can't be opened: %v", err)
	}
	base, err := basepatch.ReadBase(p, s.Running, r, uki)
	_ = c.Close()
	if err != nil {
		lg.Warn("imageupgrade: the patch's base isn't the running release", log.F("base", p.BaseVersion), log.F("running", s.Running), log.F("error", codes.Describe(err)))
		return "", err
	}
	lg.Info("imageupgrade: rebuilding the release from the patch", log.F("base", p.BaseVersion), log.F("root", p.RootSHA256), log.F("uki", p.UKISHA256))
	if err := basepatch.Rebuild(dir, p, base, uki); err != nil {
		lg.Warn("imageupgrade: the patch didn't rebuild the release", log.F("error", codes.Describe(err)))
		return "", err
	}
	lg.Info("imageupgrade: the patch rebuilt the release; staging it")
	return s.Stage(ctx, verify.LocalLayout(dir), arch)
}

// runningUKI is the UKI the box booted: the running release's ESP entry.
func (s *Stager) runningUKI() ([]byte, error) {
	entries, err := s.entries()
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Version != s.Running {
			continue
		}
		f, err := s.ESP.Open(path.Join(UKIDir, e.Name))
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("imageupgrade: read %s: %w", e.Name, err)
		}
		return b, nil
	}
	return nil, codes.New(codes.UpgradePatchBase, "the running release %s has no ESP entry to rebuild from", s.Running)
}
