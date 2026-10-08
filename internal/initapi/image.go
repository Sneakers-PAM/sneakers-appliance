// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package initapi

import (
	"context"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/imageupgrade"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
)

// Images is the work behind ImageService; *imageupgrade.Stager is the one
// the box uses.
type Images interface {
	Stage(ctx context.Context, src verify.Source, arch string) (string, error)
	Status() (imageupgrade.Status, error)
	Rollback(by string, at time.Time) error
	MarkGood(ctx context.Context, keep []string) error
	Kept() ([]string, error)
	NextStageRemoves() ([]string, error)
}

// writing is an Images that reports a Stage's progress writing the slot,
// as *imageupgrade.Stager does.
type writing interface {
	Writing() (written, total int64)
}

// imageHandler serves ImageService.
type imageHandler struct {
	initv1connect.UnimplementedImageServiceHandler
	// mu serializes the calls that write the ESP or a slot.
	mu   sync.Mutex
	im   Images
	arch string
	log  log.Logger
}

// source is the reference osadmin hands over: an unpacked OCI layout
// directory (an absolute path), or a registry reference.
func source(ref string) verify.Source {
	if filepath.IsAbs(ref) {
		return verify.LocalLayout(ref)
	}
	return verify.Registry(ref, verify.RegistryOptions{})
}

func (h *imageHandler) Stage(ctx context.Context, r *connect.Request[initv1.StageRequest]) (*connect.Response[initv1.StageResponse], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	src := source(r.Msg.GetReference())
	h.log.Info("initapi: Image.Stage", log.F("source", src.String()))
	// Under mu, the releases Stage removes are the ones named now.
	removes, err := h.im.NextStageRemoves()
	if err != nil {
		return nil, toConnect(err)
	}
	v, err := h.im.Stage(ctx, src, h.arch)
	if err != nil {
		h.log.Warn("initapi: Image.Stage refused", log.F("source", src.String()), log.F("error", codes.Describe(err)))
		return nil, toConnect(err)
	}
	h.log.Info("initapi: Image.Stage done", log.F("version", v), log.F("removed", strings.Join(removes, ",")))
	return connect.NewResponse(&initv1.StageResponse{Version: v, RemovedVersions: removes}), nil
}

// Activate checks a release is staged. Its entry already has boot tries
// and systemd-boot boots the newest entry, so the reboot that follows is
// what activates it.
func (h *imageHandler) Activate(context.Context, *connect.Request[initv1.ActivateRequest]) (*connect.Response[initv1.ActivateResponse], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	st, err := h.im.Status()
	if err != nil {
		return nil, toConnect(err)
	}
	if st.Staged == "" {
		return nil, toConnect(codes.New(codes.UpgradeNotStaged, "no release is staged"))
	}
	h.log.Info("initapi: Image.Activate", log.F("version", st.Staged))
	return connect.NewResponse(&initv1.ActivateResponse{}), nil
}

// MarkGood commits the running release: its entry loses the boot counter,
// so systemd-boot no longer falls back from it, and the sealed copies for
// UKIs no longer on the ESP are pruned. osadmin calls it once the box is up
// and healthy on the release (docs/upgrades.md).
func (h *imageHandler) MarkGood(ctx context.Context, _ *connect.Request[initv1.MarkGoodRequest]) (*connect.Response[initv1.MarkGoodResponse], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	keep, err := h.im.Kept()
	if err == nil {
		err = h.im.MarkGood(ctx, keep)
	}
	if err != nil {
		h.log.Warn("initapi: Image.MarkGood failed", log.F("error", codes.Describe(err)))
		return nil, toConnect(err)
	}
	h.log.Info("initapi: Image.MarkGood", log.F("kept", len(keep)))
	return connect.NewResponse(&initv1.MarkGoodResponse{}), nil
}

// Rollback marks the running release bad and records who asked, so the
// next boot's Status reports a revert rather than a failed boot.
func (h *imageHandler) Rollback(_ context.Context, r *connect.Request[initv1.RollbackRequest]) (*connect.Response[initv1.RollbackResponse], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.im.Rollback(r.Msg.GetBy(), time.Now()); err != nil {
		h.log.Warn("initapi: Image.Rollback refused", log.F("error", codes.Describe(err)))
		return nil, toConnect(err)
	}
	h.log.Info("initapi: Image.Rollback", log.F("by", r.Msg.GetBy()))
	return connect.NewResponse(&initv1.RollbackResponse{}), nil
}

func (h *imageHandler) Status(context.Context, *connect.Request[initv1.ImageServiceStatusRequest]) (*connect.Response[initv1.ImageServiceStatusResponse], error) {
	st, err := h.im.Status()
	if err != nil {
		return nil, toConnect(err)
	}
	out := &initv1.ImageServiceStatusResponse{RunningVersion: st.Running, StagedVersion: st.Staged, FailedVersion: st.Failed, PreviousVersion: st.Previous, NextStageRemoves: st.NextStageRemoves}
	if w, ok := h.im.(writing); ok {
		out.StageWrittenBytes, out.StageTotalBytes = w.Writing()
	}
	if rev := st.Reverted; rev.Version != "" {
		out.RevertedVersion, out.RevertedBy, out.RevertedAt = rev.Version, rev.By, timestamppb.New(rev.At)
	}
	return connect.NewResponse(out), nil
}

func imageHandlerFor(o Options) (string, http.Handler) {
	if o.Images == nil {
		return initv1connect.NewImageServiceHandler(initv1connect.UnimplementedImageServiceHandler{})
	}
	return initv1connect.NewImageServiceHandler(&imageHandler{im: o.Images, arch: runtime.GOARCH, log: o.Logger})
}
