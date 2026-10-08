// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
)

// The box's phases, as GetPhase and GetStatus answer them.
const (
	// PhaseFirstBoot runs until setup's Finish.
	PhaseFirstBoot = "firstboot"
	// PhaseNormal follows.
	PhaseNormal = "normal"
)

// SetupPath is the setup stepper's page, the only page served before
// setup is done.
const SetupPath = "/setup"

// Phase is the box's phase.
func (s *Server) Phase() string {
	if s.SetupDone() {
		return PhaseNormal
	}
	return PhaseFirstBoot
}

func (h *status) GetPhase(ctx context.Context, _ *connect.Request[osadminv1.GetPhaseRequest]) (*connect.Response[osadminv1.GetPhaseResponse], error) {
	p := h.s.Phase()
	running := h.s.productRunning(ctx)
	return connect.NewResponse(&osadminv1.GetPhaseResponse{
		Phase: p, State: string(h.s.boxState(p, running)), ProductRunning: running,
		ProductInstalled: h.s.slots().Status().Installed != "",
	}), nil
}

// boxState is what the box is doing, as the product edge's box-state page
// shows it. An update holds over the reboot it ends in, so the page says
// why the box went away; init's announcement of a reboot or a shutdown
// holds over everything else.
func (s *Server) boxState(phase string, productRunning bool) boxstate.State {
	announced := boxstate.State("")
	if s.o.BoxStateFile != "" {
		announced = boxstate.Read(s.o.BoxStateFile)
	}
	switch {
	case s.Maintenance():
		return boxstate.Updating
	case announced != "":
		return announced
	case phase != PhaseNormal || !productRunning:
		return boxstate.Starting
	default:
		return boxstate.Running
	}
}

// productStatusTimeout bounds asking init about the product's service, so
// a slow init doesn't hold up the public GetPhase.
const productStatusTimeout = 2 * time.Second

// productRunning asks init whether the product's service runs; with no
// answer it doesn't.
func (s *Server) productRunning(ctx context.Context) bool {
	if s.o.Services == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, productStatusTimeout)
	defer cancel()
	r, err := s.o.Services.Status(ctx, connect.NewRequest(&initv1.StatusRequest{Name: ProductService}))
	if err != nil {
		s.o.Logger.Debug("osadmin: the product service's state isn't known", log.F("error", err.Error()))
		return false
	}
	return r.Msg.GetRunning()
}

// PagesHandler is StaticHandler gated on the phase: while phase answers
// PhaseFirstBoot, every page path but /setup (/, the sign-in page,
// included) is redirected to /setup. The files the pages load are served
// in every phase. When phase fails the pages are served as they are; the
// API refuses what the phase doesn't allow either way.
func PagesHandler(assets fs.FS, phase func(*http.Request) (string, error), lg log.Logger) http.Handler {
	if lg == nil {
		lg = log.Nop()
	}
	static := StaticHandler(assets)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == SetupPath || r.URL.Path == SetupPath+"/" || isAsset(assets, r.URL.Path) {
			static.ServeHTTP(w, r)
			return
		}
		p, err := phase(r)
		if err != nil {
			lg.Warn("osadmin: the phase isn't known; the page is served", log.F("path", r.URL.Path), log.F("error", err.Error()))
			static.ServeHTTP(w, r)
			return
		}
		if p == PhaseFirstBoot {
			lg.Debug("osadmin: setup isn't done; the page goes to /setup", log.F("path", r.URL.Path))
			http.Redirect(w, r, SetupPath, http.StatusFound)
			return
		}
		static.ServeHTTP(w, r)
	})
}

// isAsset is whether p names one of the pages' files: anything but the
// index (the page every route is served from) and a directory.
func isAsset(assets fs.FS, p string) bool {
	if assets == nil {
		return false
	}
	name := strings.TrimPrefix(path.Clean(p), "/")
	if name == "" || name == "." || name == "index.html" {
		return false
	}
	st, err := fs.Stat(assets, name)
	return err == nil && !st.IsDir()
}
