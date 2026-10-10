// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

// readiness is whether the product has been ready since k0s last started.
// Until it has, the box state isn't running, so the edge answers 443 with
// the box-state page and an open tab keeps its overlay instead of reloading
// into a product whose services are still starting (docs/edge-fallback.md).
type readiness struct {
	mu sync.Mutex
	// ready: the probe answered ready since k0s started.
	ready bool
	// failed is the step that failed and why, "<label>: <why>": a phase
	// that failed or timed out, or a product not ready within its bound.
	// The box says failed until k0s starts again.
	failed, failedStep string
	// held: a phased product is held while an import is open; the box
	// says maintenance.
	held bool
	// since is when k0s was first seen running without the product ready;
	// step and stepSince the step it was last seen on, and since when.
	since, stepSince time.Time
	step             string
	// asking: a probe runs; askedAt is when the last one started, on the
	// process's own clock (it only spaces the asks out).
	asking  bool
	askedAt time.Time
}

// productReadyNow says whether the product counts as ready for the box
// state, given whether k0s runs. It never waits on the probe: a probe runs
// in the background at most every ProductUpEvery and its answer counts
// from the next ask (a phased product's probe also moves it on to its
// next phase). A product that isn't ready within its ready bound, or a
// phase that fails or isn't ready within its own timeout, leaves the box
// failed rather than serving a half-started product. With no probe the
// product is ready as soon as k0s runs.
func (s *Server) productReadyNow(running bool) bool {
	if s.o.ProductUp == nil {
		return running
	}
	r := &s.ready
	r.mu.Lock()
	defer r.mu.Unlock()
	if !running {
		if r.ready || !r.since.IsZero() || r.failed != "" || r.held {
			s.o.Logger.Debug("osadmin: k0s doesn't run; the product waits for its readiness again at the next start")
		}
		r.reset()
		return false
	}
	if r.ready {
		return true
	}
	now := s.o.Clock.Now()
	if r.since.IsZero() {
		r.since, r.stepSince = now, now
		s.o.Logger.Info("osadmin: k0s runs; the box says starting until the product is ready")
	}
	if r.failed != "" {
		return false
	}
	if bound := s.productUpBound(); !r.held && now.Sub(r.since) > bound {
		r.failed, r.failedStep = fmt.Sprintf("%s: the product isn't ready after %s", s.stepLabel(r.step), bound), r.step
		go s.boxChanged()
		s.o.Logger.Warn("osadmin: the product isn't ready within its bound; the box says failed", log.F("bound", bound.String()), log.F("step", r.step))
		return false
	}
	every := s.o.Upgrade.ProductUpEvery
	if every <= 0 {
		every = DefaultProductUpEvery
	}
	if !r.asking && time.Since(r.askedAt) >= every {
		r.asking, r.askedAt = true, time.Now()
		since := r.since
		go s.askReady(since, every)
	}
	return false
}

func (r *readiness) reset() {
	r.ready, r.held, r.failed, r.failedStep, r.step = false, false, "", "", ""
	r.since, r.stepSince = time.Time{}, time.Time{}
}

// askReady runs the probe once and records its answer, unless k0s started
// again meanwhile: ready, held, a failed phase, or the step it's on.
func (s *Server) askReady(since time.Time, every time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), every+10*time.Second)
	defer cancel()
	var res productup.Result
	var err error
	if s.o.ProductUp != nil {
		res, err = s.o.ProductUp.Check(ctx)
	}
	r := &s.ready
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asking = false
	if !r.since.Equal(since) || r.failed != "" {
		return
	}
	now := s.o.Clock.Now()
	switch {
	case err != nil:
		s.o.Logger.Debug("osadmin: the product's state isn't known this time", log.F("error", err.Error()))
		return
	case res.Step == "":
		r.ready, r.held = true, false
		defer s.boxChanged()
		s.o.Logger.Info("osadmin: the product is ready; the box says running", log.F("seconds", int(now.Sub(since).Seconds())))
		return
	case res.Held:
		if !r.held {
			defer s.boxChanged()
			s.o.Logger.Info("osadmin: the product is held while an import is open; the box says maintenance", log.F("step", res.Step))
		}
		r.held, r.since = true, now
		return
	}
	if r.held {
		defer s.boxChanged()
		r.held, r.since = false, now
	}
	if res.Step != r.step {
		r.step, r.stepSince = res.Step, now
	}
	switch {
	case res.Failed:
		r.failed = s.stepLabel(res.Step) + ": " + res.Detail
	case res.Timeout > 0 && now.Sub(r.stepSince) > res.Timeout:
		r.failed = fmt.Sprintf("%s: not ready after %s: %s", s.stepLabel(res.Step), res.Timeout, res.Detail)
	default:
		s.o.Logger.Debug("osadmin: the product isn't ready yet", log.F("step", res.Step), log.F("waiting", res.Detail))
		return
	}
	r.failedStep = res.Step
	defer s.boxChanged()
	s.o.Logger.Warn("osadmin: a phase of the product failed; the box says failed", log.F("step", res.Step), log.F("why", r.failed))
}

// productWaitsAgain is a product restart: the product must be ready again
// before the box says running.
func (s *Server) productWaitsAgain() {
	s.ready.mu.Lock()
	defer s.ready.mu.Unlock()
	s.ready.reset()
}

// productIsReady records the product ready, as a product apply's or
// revert's follower saw it.
func (s *Server) productIsReady() {
	defer s.boxChanged()
	s.ready.mu.Lock()
	defer s.ready.mu.Unlock()
	s.ready.ready, s.ready.held = true, false
}

// productHeld records the product held while an import is open, as a
// product apply's or revert's follower saw it.
func (s *Server) productHeld(res productup.Result) {
	defer s.boxChanged()
	s.ready.mu.Lock()
	defer s.ready.mu.Unlock()
	s.ready.held, s.ready.since = true, s.o.Clock.Now()
	s.ready.step = res.Step
}

// productFailed records a failed step and why, "<label>: <why>": the box
// says failed until k0s starts again.
func (s *Server) productFailed(step, why string) {
	defer s.boxChanged()
	s.ready.mu.Lock()
	defer s.ready.mu.Unlock()
	s.ready.failed, s.ready.failedStep = why, step
}

// productFailure is the failed step and why, or "" when nothing failed.
func (s *Server) productFailure() (step, why string) {
	s.ready.mu.Lock()
	defer s.ready.mu.Unlock()
	return s.ready.failedStep, s.ready.failed
}

// productHeldNow is whether an import holds the product.
func (s *Server) productHeldNow() bool {
	s.ready.mu.Lock()
	defer s.ready.mu.Unlock()
	return s.ready.held
}

// productComingUp is whether a product apply or revert follows the product
// coming up after its restart.
func (s *Server) productComingUp() bool {
	r := s.progressSnapshot()
	return r != nil && isProductUpStep(r.active())
}
