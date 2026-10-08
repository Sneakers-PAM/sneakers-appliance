// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package initapi

import (
	"context"
	"net/http"
	"path/filepath"
	"runtime"
	"sync"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

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
	Rollback() error
}

// imageHandler serves ImageService. MarkGood stays unimplemented until the
// post-boot health check that calls it exists.
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
	v, err := h.im.Stage(ctx, src, h.arch)
	if err != nil {
		h.log.Warn("initapi: Image.Stage refused", log.F("source", src.String()), log.F("error", codes.Describe(err)))
		return nil, toConnect(err)
	}
	h.log.Info("initapi: Image.Stage done", log.F("version", v))
	return connect.NewResponse(&initv1.StageResponse{Version: v}), nil
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

func (h *imageHandler) Rollback(context.Context, *connect.Request[initv1.RollbackRequest]) (*connect.Response[initv1.RollbackResponse], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.im.Rollback(); err != nil {
		h.log.Warn("initapi: Image.Rollback refused", log.F("error", codes.Describe(err)))
		return nil, toConnect(err)
	}
	h.log.Info("initapi: Image.Rollback")
	return connect.NewResponse(&initv1.RollbackResponse{}), nil
}

func (h *imageHandler) Status(context.Context, *connect.Request[initv1.ImageServiceStatusRequest]) (*connect.Response[initv1.ImageServiceStatusResponse], error) {
	st, err := h.im.Status()
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&initv1.ImageServiceStatusResponse{RunningVersion: st.Running, StagedVersion: st.Staged, FailedVersion: st.Failed}), nil
}

func imageHandlerFor(o Options) (string, http.Handler) {
	if o.Images == nil {
		return initv1connect.NewImageServiceHandler(initv1connect.UnimplementedImageServiceHandler{})
	}
	return initv1connect.NewImageServiceHandler(&imageHandler{im: o.Images, arch: runtime.GOARCH, log: o.Logger})
}
