// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"fmt"
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

// checkBound bounds one ask of the product: a phased product's ask runs
// several k0s commands in turn, each bounded on its own, and a box that
// has just started k0s answers them slowly.
const checkBound = 2 * time.Minute

// unreadable leads a step's detail when the product's state can't be
// read.
const unreadable = "the product's state can't be read: "

// productUpSteps follow restarting the product, all pending.
var productUpSteps = []progressStep{
	{ID: productup.StepK0s, Label: "Starting k0s", State: statePending},
	{ID: productup.StepImages, Label: "Importing the images", State: statePending},
	{ID: productup.StepManifests, Label: "Applying the product's stacks", State: statePending},
	{ID: productup.StepPods, Label: "Rolling out", State: statePending},
	{ID: productup.StepHealth, Label: "Checking the product's health", State: statePending},
	{ID: productup.StepEdge, Label: "Opening the product on 443", State: statePending},
}

func isProductUpStep(id string) bool { return productup.IsStep(id) }

// productStepper is a probe that knows the installed slot's own steps: a
// phased product has one per phase (productup.Probe.Steps).
type productStepper interface {
	Steps() []productup.Step
}

// useSlotSteps puts the installed slot's steps in place of the record's
// coming-up steps, once the slot has switched.
func (s *Server) useSlotSteps() {
	st, ok := s.o.ProductUp.(productStepper)
	if !ok {
		return
	}
	steps := st.Steps()
	s.progress.mu.Lock()
	defer s.progress.mu.Unlock()
	s.loadProgress()
	r := s.progress.rec
	if r == nil {
		return
	}
	var kept []progressStep
	for _, x := range r.Steps {
		if !isProductUpStep(x.ID) {
			kept = append(kept, x)
		}
	}
	for _, x := range steps {
		kept = append(kept, progressStep{ID: x.ID, Label: x.Label, State: statePending})
	}
	r.Steps = kept
	s.saveProgressLocked()
}

// stepLabel is the record's label for step id, or id.
func (s *Server) stepLabel(id string) string {
	if r := s.progressSnapshot(); r != nil {
		if i := r.find(id); i >= 0 {
			return r.Steps[i].Label
		}
	}
	if st, ok := s.o.ProductUp.(productStepper); ok {
		for _, x := range st.Steps() {
			if x.ID == id {
				return x.Label
			}
		}
	}
	return id
}

// startProductUp begins following the product after its restart: the
// first step is active and a goroutine follows the rest, so the apply
// answers while Updates and the console show the product coming up.
func (s *Server) startProductUp() {
	s.productWaitsAgain()
	s.useSlotSteps()
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

// followProductUp starts the follower unless one follows this record
// already. One still following an earlier record (its Check hadn't
// answered yet when the record moved on) doesn't hold it up: it ends at
// its next look.
func (s *Server) followProductUp() {
	s.progress.mu.Lock()
	if s.progress.stopped || s.progress.rec == nil {
		s.progress.mu.Unlock()
		return
	}
	started := s.progress.rec.Started
	if s.progress.following && s.progress.followed.Equal(started) {
		s.progress.mu.Unlock()
		return
	}
	if s.progress.following {
		s.o.Logger.Info("osadmin: an earlier follower is still out; a new one follows this record", log.F("version", s.progress.rec.Version))
		if s.progress.ask != nil {
			s.progress.ask()
		}
	}
	if s.progress.stop == nil {
		s.progress.stop = make(chan struct{})
	}
	s.progress.gen++
	gen, at := s.progress.gen, s.progress.rec.active()
	s.progress.following, s.progress.followed = true, started
	s.progress.done.Add(1)
	stop := s.progress.stop
	s.progress.mu.Unlock()
	s.o.Logger.Info("osadmin: following the product coming up", log.F("step", at))
	go func() {
		defer s.progress.done.Done()
		defer func() {
			s.progress.mu.Lock()
			if s.progress.gen == gen {
				s.progress.following = false
			}
			s.progress.mu.Unlock()
		}()
		s.productUpLoop(started, stop)
	}()
}

// callOffAsks ends every ask of the product in flight, the follower's and
// the box state's: the product is about to stop, and an ask begun before
// must never act (quiesce or place stacks) on what comes up after.
func (s *Server) callOffAsks() {
	s.progress.mu.Lock()
	if s.progress.ask != nil {
		s.progress.ask()
	}
	s.progress.mu.Unlock()
	s.ready.mu.Lock()
	if s.ready.cancel != nil {
		s.ready.cancel()
	}
	s.ready.mu.Unlock()
}

// followIfNone starts the follower when a product apply's or revert's
// record is coming up and nothing follows it, so the record never sits
// on a step with nothing moving the product on.
func (s *Server) followIfNone() {
	if s.o.ProductUp == nil || !s.productComingUp() {
		return
	}
	s.progress.mu.Lock()
	idle := !s.progress.following && !s.progress.stopped
	s.progress.mu.Unlock()
	if idle {
		s.o.Logger.Warn("osadmin: the product is coming up with nothing following it; following it again")
		s.followProductUp()
	}
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

// productReady answers whether the product is ready now for the import's
// verify, and what it waits for when it isn't: held while the import is
// open counts as ready. With no probe it counts as ready.
func (s *Server) productReady(ctx context.Context) (bool, string) {
	if s.o.ProductUp == nil {
		return true, ""
	}
	res, err := s.o.ProductUp.Check(ctx)
	switch {
	case err != nil:
		return false, "its state isn't known: " + err.Error()
	case res.Held:
		// An open import holds the product after the phases it writes
		// to: for the import's own steps that's ready.
		return true, ""
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
	stepSince := since
	last := productup.Result{Step: "-"}
	lastErr := ""
	for {
		r := s.progressSnapshot()
		if r == nil || !r.Started.Equal(started) || !isProductUpStep(r.active()) {
			s.o.Logger.Info("osadmin: stopped following the product; the record moved on")
			return
		}
		at := r.active()
		ctx, cancel := context.WithTimeout(context.Background(), checkBound)
		s.progress.mu.Lock()
		s.progress.ask = cancel
		s.progress.mu.Unlock()
		res, err := s.o.ProductUp.Check(ctx)
		cancel()
		now := s.o.Clock.Now()
		switch {
		case err != nil:
			// The product's state can't be read this time: said on the
			// step and logged when it changes, and held to the bound as
			// the reason.
			if msg := err.Error(); msg != lastErr {
				lastErr = msg
				s.o.Logger.Warn("osadmin: the product's progress can't be read", log.F("step", at), log.F("error", msg))
				s.setStep(at, unreadable+msg)
			}
		case res.Step == "" || res.Held:
			if res.Held {
				s.productHeld(res)
				s.o.Logger.Info("osadmin: the product is held while an import is open", log.F("step", res.Step))
			} else {
				s.productIsReady()
			}
			s.finishSteps(productup.StepEdge)
			if h := s.takeHeld(started); h != nil {
				s.writeHeld(h, nil, "")
			}
			s.o.Logger.Info("osadmin: the product is up", log.F("version", r.Version), log.F("seconds", int(now.Sub(since).Seconds())))
			return
		case res != last || lastErr != "":
			if res.Step != last.Step {
				stepSince = now
				s.o.Logger.Info("osadmin: the product is at a new step", log.F("step", res.Step), log.F("detail", res.Detail))
			}
			last, lastErr = res, ""
			at = res.Step
			s.setStep(res.Step, res.Detail)
		}
		var why string
		switch {
		case err == nil && res.Failed:
			why = "it can't start: " + res.Detail
		case err == nil && res.Timeout > 0 && now.Sub(stepSince) > res.Timeout:
			why = fmt.Sprintf("it isn't ready after %s: %s", res.Timeout, res.Detail)
		case err != nil && last.Timeout > 0 && last.Step == at && now.Sub(stepSince) > last.Timeout:
			why = fmt.Sprintf("it isn't ready after %s: %s%s", last.Timeout, unreadable, lastErr)
		case now.Sub(since) > s.productUpBound():
			waiting := last.Detail
			if lastErr != "" {
				waiting = unreadable + lastErr
			}
			if waiting == "" {
				waiting = "the step " + at + " didn't finish"
			}
			why = fmt.Sprintf("the product isn't ready after %s: %s", s.productUpBound(), waiting)
		}
		if why != "" {
			s.productUpFailed(r, started, at, why)
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

// productUpFailed fails a product apply's or revert's step at with why:
// the record, the history, the audit log and the box state, which says
// failed with the step's label and why until k0s starts again.
func (s *Server) productUpFailed(r *progressRecord, started time.Time, at, why string) {
	label := s.stepLabel(at)
	err := codes.New(codes.UpgradeProductStart, "%s: %s; Status and the root shell's kubectl show what holds it", label, why)
	s.failStep(at, err)
	if h := s.takeHeld(started); h != nil {
		s.writeHeld(h, err, why)
	} else {
		s.historyFor(osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT, r.Action, r.Version, "osadmin", err, why)
	}
	s.write(osaudit.Entry{Actor: "osadmin", Action: "upgrade.product-not-ready", Target: "product", Detail: map[string]string{"version": r.Version, "action": r.Action, "step": at, "why": why}}, err)
	s.o.Logger.Warn("osadmin: the product didn't come up; the update failed", log.F("action", r.Action), log.F("version", r.Version), log.F("step", at), log.F("why", why))
	s.productFailed(at, label+": "+why)
	s.consoleChanged()
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
