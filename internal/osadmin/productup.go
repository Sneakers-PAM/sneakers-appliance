// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

// ProductProbe tells how far the product has come up.
type ProductProbe interface {
	Check(ctx context.Context) (productup.Result, error)
}

// ProductUpBound is how long a product may take to be ready after its
// restart before the step it's on fails with UPGRADE_PRODUCT_START, unless
// the installed product.yaml says otherwise (ready.timeout).
const ProductUpBound = 10 * time.Minute

// DefaultProductUpEvery is how often the product is asked while it comes
// up.
const DefaultProductUpEvery = 3 * time.Second

// productUpSteps follow restarting the product, all pending.
var productUpSteps = []progressStep{
	{ID: productup.StepK0s, Label: "Starting k0s", State: statePending},
	{ID: productup.StepImages, Label: "Importing the images", State: statePending},
	{ID: productup.StepManifests, Label: "Applying the product's stacks", State: statePending},
	{ID: productup.StepPods, Label: "Rolling out", State: statePending},
	{ID: productup.StepHealth, Label: "Checking the product's health", State: statePending},
	{ID: productup.StepEdge, Label: "Opening the product on 443", State: statePending},
}

func isProductUpStep(id string) bool {
	for _, s := range productUpSteps {
		if s.ID == id {
			return true
		}
	}
	return false
}

// startProductUp begins following the product after its restart: the
// first step is active and a goroutine follows the rest, so the apply
// answers while Updates and the console show the product coming up.
func (s *Server) startProductUp() {
	s.setStep(productup.StepK0s, "")
	s.followProductUp()
}

// ResumeProductUp picks up following the product when accessd restarted
// while it came up; accessd calls it at start.
func (s *Server) ResumeProductUp() {
	if s.o.ProductUp == nil {
		return
	}
	r := s.progressSnapshot()
	if r == nil || !isProductUpStep(r.active()) {
		return
	}
	s.o.Logger.Info("osadmin: following the product coming up again after a restart", log.F("step", r.active()), log.F("version", r.Version))
	s.followProductUp()
}

// followProductUp starts the follower unless one runs.
func (s *Server) followProductUp() {
	s.progress.mu.Lock()
	if s.progress.following || s.progress.stopped || s.progress.rec == nil {
		s.progress.mu.Unlock()
		return
	}
	if s.progress.stop == nil {
		s.progress.stop = make(chan struct{})
	}
	s.progress.following = true
	started := s.progress.rec.Started
	s.progress.done.Add(1)
	stop := s.progress.stop
	s.progress.mu.Unlock()
	go func() {
		defer s.progress.done.Done()
		defer func() {
			s.progress.mu.Lock()
			s.progress.following = false
			s.progress.mu.Unlock()
		}()
		s.productUpLoop(started, stop)
	}()
}

// Close stops following the product and waits for it; the record keeps
// the step it was on, and ResumeProductUp picks it up at the next start.
func (s *Server) Close() {
	s.progress.mu.Lock()
	if !s.progress.stopped {
		s.progress.stopped = true
		if s.progress.stop != nil {
			close(s.progress.stop)
		}
	}
	s.progress.mu.Unlock()
	s.progress.done.Wait()
}

// productUpBound is how long the installed product may take to be ready:
// its product.yaml's ready.timeout, else ProductUpBound.
func (s *Server) productUpBound() time.Duration {
	if _, spec := s.installedSpec(); spec.ReadyTimeout() > 0 {
		return spec.ReadyTimeout()
	}
	return ProductUpBound
}

// productReady answers whether the product is ready now, and what it
// waits for when it isn't; with no probe it counts as ready.
func (s *Server) productReady(ctx context.Context) (bool, string) {
	if s.o.ProductUp == nil {
		return true, ""
	}
	res, err := s.o.ProductUp.Check(ctx)
	switch {
	case err != nil:
		return false, "its state isn't known: " + err.Error()
	case res.Step != "":
		if res.Detail != "" {
			return false, res.Detail
		}
		return false, "it's at the step " + res.Step
	}
	return true, ""
}

// productUpLoop asks the probe until the product is ready (every workload
// rolled out, its health check and 443 answering), the bound passes or
// another update replaces the record.
func (s *Server) productUpLoop(started time.Time, stop <-chan struct{}) {
	every := s.o.Upgrade.ProductUpEvery
	if every <= 0 {
		every = DefaultProductUpEvery
	}
	since := s.o.Clock.Now()
	last := productup.Result{Step: "-"}
	for {
		r := s.progressSnapshot()
		if r == nil || !r.Started.Equal(started) || !isProductUpStep(r.active()) {
			s.o.Logger.Debug("osadmin: stopped following the product; the record moved on")
			return
		}
		at := r.active()
		ctx, cancel := context.WithTimeout(context.Background(), every+10*time.Second)
		res, err := s.o.ProductUp.Check(ctx)
		cancel()
		switch {
		case err != nil:
			s.o.Logger.Debug("osadmin: the product's progress isn't known this time", log.F("step", at), log.F("error", err.Error()))
		case res.Step == "":
			s.finishSteps(productup.StepEdge)
			if h := s.takeHeld(started); h != nil {
				s.writeHeld(h, nil, "")
			}
			s.o.Logger.Info("osadmin: the product is up", log.F("version", r.Version), log.F("seconds", int(s.o.Clock.Now().Sub(since).Seconds())))
			return
		case res != last:
			last = res
			at = res.Step
			s.setStep(res.Step, res.Detail)
		}
		if bound := s.productUpBound(); s.o.Clock.Now().Sub(since) > bound {
			waiting := last.Detail
			if waiting == "" {
				waiting = "the step " + at + " didn't finish"
			}
			err := codes.New(codes.UpgradeProductStart, "the product isn't ready after %s: %s; Status and the root shell's kubectl show what holds it", bound, waiting)
			s.failStep(at, err)
			if h := s.takeHeld(started); h != nil {
				s.writeHeld(h, err, "not ready after "+bound.String())
			} else {
				s.historyFor(osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT, r.Action, r.Version, "osadmin", err, "not ready after "+bound.String())
			}
			s.write(osaudit.Entry{Actor: "osadmin", Action: "upgrade.product-not-ready", Target: "product", Detail: map[string]string{"version": r.Version, "action": r.Action, "step": at, "waited": bound.String()}}, err)
			s.o.Logger.Warn("osadmin: the product isn't ready within the bound; the update failed", log.F("action", r.Action), log.F("version", r.Version), log.F("step", at), log.F("waiting", waiting), log.F("bound", bound.String()))
			s.consoleChanged()
			return
		}
		select {
		case <-stop:
			s.o.Logger.Info("osadmin: stopped following the product; osadmin is stopping", log.F("step", at))
			return
		case <-time.After(every):
		}
	}
}

// productHistory records a product apply's or revert's outcome. One that
// failed, or that nothing follows, goes into the history at once; one the
// product is still coming up from is held in the record and written once
// the product is ready, or fails within the bound, so the history never
// says ok before the steps do.
func (s *Server) productHistory(action, version, actor string, err error, detail string) {
	e := &historyEntry{Action: action, Version: version, Actor: actor, Detail: detail, Target: targetName(osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT)}
	if err == nil && s.o.ProductUp != nil && s.holdHistory(e) {
		s.o.Logger.Debug("osadmin: the product's history entry waits until it's ready", log.F("action", action), log.F("version", version))
		return
	}
	s.writeHeld(e, err, "")
}

// holdHistory keeps e in the record while the product is coming up; false
// when it isn't (it was ready already).
func (s *Server) holdHistory(e *historyEntry) bool {
	s.progress.mu.Lock()
	defer s.progress.mu.Unlock()
	s.loadProgress()
	r := s.progress.rec
	if r == nil || !isProductUpStep(r.active()) {
		return false
	}
	r.History = e
	s.saveProgressLocked()
	return true
}

// takeHeld takes the history entry the record started at started holds.
func (s *Server) takeHeld(started time.Time) *historyEntry {
	s.progress.mu.Lock()
	defer s.progress.mu.Unlock()
	r := s.progress.rec
	if r == nil || !r.Started.Equal(started) || r.History == nil {
		return nil
	}
	h := r.History
	r.History = nil
	s.saveProgressLocked()
	return h
}

// writeHeld writes a held entry with the outcome err, more added to its
// detail.
func (s *Server) writeHeld(h *historyEntry, err error, more string) {
	detail := h.Detail
	if more != "" {
		if detail != "" {
			detail += "; "
		}
		detail += more
	}
	s.historyFor(targetOf(h.Target), h.Action, h.Version, h.Actor, err, detail)
}
