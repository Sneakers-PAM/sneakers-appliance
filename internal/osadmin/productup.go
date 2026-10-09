// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

// ProductProbe tells how far the product has come up.
type ProductProbe interface {
	Check(ctx context.Context) (productup.Result, error)
}

// ProductUpBound is how long a product may take to come up after its
// restart before the step it's on fails with UPGRADE_PRODUCT_START.
const ProductUpBound = 20 * time.Minute

// DefaultProductUpEvery is how often the product is asked while it comes
// up.
const DefaultProductUpEvery = 3 * time.Second

// productUpSteps follow restarting the product, all pending.
var productUpSteps = []progressStep{
	{ID: productup.StepK0s, Label: "Starting k0s", State: statePending},
	{ID: productup.StepImages, Label: "Importing the images", State: statePending},
	{ID: productup.StepManifests, Label: "Applying the product's stacks", State: statePending},
	{ID: productup.StepPods, Label: "Waiting for the pods to be ready", State: statePending},
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

// productUpLoop asks the probe until the product answers on 443, the
// bound passes or another update replaces the record.
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
			s.o.Logger.Info("osadmin: the product is up", log.F("version", r.Version), log.F("seconds", int(s.o.Clock.Now().Sub(since).Seconds())))
			return
		case res != last:
			last = res
			at = res.Step
			s.setStep(res.Step, res.Detail)
		}
		if s.o.Clock.Now().Sub(since) > ProductUpBound {
			s.failStep(at, codes.New(codes.UpgradeProductStart, "the product didn't come up within %s; Status and the root shell's kubectl show what holds it", ProductUpBound))
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
