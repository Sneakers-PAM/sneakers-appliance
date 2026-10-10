// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
)

// readiness is whether the product has been ready since k0s last started.
// Until it has, the box state isn't running, so the edge answers 443 with
// the box-state page and an open tab keeps its overlay instead of reloading
// into a product whose services are still starting (docs/edge-fallback.md).
type readiness struct {
	mu sync.Mutex
	// ready: the probe answered ready (or gave up) since k0s started.
	ready bool
	// since is when k0s was first seen running without the product ready.
	since time.Time
	// asking: a probe runs; askedAt is when the last one started, on the
	// process's own clock (it only spaces the asks out).
	asking  bool
	askedAt time.Time
}

// productReadyNow says whether the product counts as ready for the box
// state, given whether k0s runs. It never waits on the probe: a probe runs
// in the background at most every ProductUpEvery and its answer counts
// from the next ask. A product that isn't ready within its ready bound
// counts as ready, so a partly broken product stays reachable. With no
// probe the product is ready as soon as k0s runs.
func (s *Server) productReadyNow(running bool) bool {
	if s.o.ProductUp == nil {
		return running
	}
	r := &s.ready
	r.mu.Lock()
	defer r.mu.Unlock()
	if !running {
		if r.ready || !r.since.IsZero() {
			s.o.Logger.Debug("osadmin: k0s doesn't run; the product waits for its readiness again at the next start")
		}
		r.ready, r.since = false, time.Time{}
		return false
	}
	if r.ready {
		return true
	}
	now := s.o.Clock.Now()
	if r.since.IsZero() {
		r.since = now
		s.o.Logger.Info("osadmin: k0s runs; the box says starting until the product is ready")
	}
	if bound := s.productUpBound(); now.Sub(r.since) > bound {
		r.ready = true
		s.o.Logger.Warn("osadmin: the product isn't ready within its bound; the box says running so what works can be reached", log.F("bound", bound.String()))
		return true
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

// askReady runs the probe once and records a ready answer, unless k0s
// started again meanwhile.
func (s *Server) askReady(since time.Time, every time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), every+10*time.Second)
	defer cancel()
	ok, waiting := s.productReady(ctx)
	r := &s.ready
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asking = false
	if !r.since.Equal(since) {
		return
	}
	if ok {
		r.ready = true
		s.o.Logger.Info("osadmin: the product is ready; the box says running", log.F("seconds", int(s.o.Clock.Now().Sub(since).Seconds())))
		return
	}
	s.o.Logger.Debug("osadmin: the product isn't ready yet", log.F("waiting", waiting))
}

// productWaitsAgain is a product restart: the product must be ready again
// before the box says running.
func (s *Server) productWaitsAgain() {
	s.ready.mu.Lock()
	defer s.ready.mu.Unlock()
	s.ready.ready, s.ready.since = false, time.Time{}
}

// productIsReady records the product ready, as a product apply's or
// revert's follower saw it.
func (s *Server) productIsReady() {
	s.ready.mu.Lock()
	defer s.ready.mu.Unlock()
	s.ready.ready = true
}

// productComingUp is whether a product apply or revert follows the product
// coming up after its restart.
func (s *Server) productComingUp() bool {
	r := s.progressSnapshot()
	return r != nil && isProductUpStep(r.active())
}
