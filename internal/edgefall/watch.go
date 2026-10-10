// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package edgefall

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
)

// Phase is what accessd's public GetPhase answers that edgefall uses, or
// what accessd pushes the moment it changes.
type Phase struct {
	State            string `json:"state"`
	ProductRunning   bool   `json:"productRunning"`
	ProductInstalled bool   `json:"productInstalled"`
	// Kind is what an updating box is doing: KindUpdate or
	// KindProductApply; empty is an update.
	Kind string `json:"kind,omitempty"`
	// Step is the update's active step id, Detail its words.
	Step   string `json:"step,omitempty"`
	Detail string `json:"detail,omitempty"`
	// Reset, on a push, drops a reboot or a shutdown seen before: accessd
	// says it was refused, so the box isn't going after all.
	Reset bool `json:"reset,omitempty"`
}

// Source asks accessd's GetPhase.
type Source func(ctx context.Context) (Phase, error)

// Watcher keeps the box state edgefall serves and whether it holds 80 and
// 443. Requests never wait on accessd: they read what the last poll left.
type Watcher struct {
	src  Source
	file string
	lg   log.Logger

	mu    sync.Mutex
	state boxstate.State
	// going: a reboot or a shutdown was seen; it holds until the box is
	// gone, through accessd's drain.
	going bool
	// installed: accessd last said a product bundle is installed.
	installed bool
	claim     bool
	// stopped: accessd last said the product doesn't run. startedAt is
	// when it was then seen running, so the edge stays held until the
	// edge asks for it (handedOff) or HandoffWait passes.
	stopped   bool
	startedAt time.Time
	handedOff bool
	now       func() time.Time
	// events streams the state (EventsPath); kind, step and detail go
	// with it.
	events             *Hub
	kind, step, detail string
}

// HandoffWait is how long edgefall keeps 80 and 443 after k0s starts when
// the product's edge doesn't ask for them: today's behaviour for an edge
// without the handoff, a little later.
const HandoffWait = 2 * time.Minute

// SetClock replaces time.Now, for tests.
func (w *Watcher) SetClock(now func() time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.now = now
}

// Handoff is the edge asking for 80 and 443, just before Traefik binds
// them: taken only while k0s runs and edgefall still holds them for it.
func (w *Watcher) Handoff() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.startedAt.IsZero() || w.handedOff || w.going {
		w.lg.Debug("edgefall: a handoff that isn't waited for; ignored", log.F("state", string(w.state)))
		return false
	}
	w.handedOff = true
	w.claim = false
	w.lg.Info("edgefall: the edge asked for 80 and 443; letting them go", log.F("waited", w.now().Sub(w.startedAt).String()))
	return true
}

// holding is whether k0s started after edgefall saw it stopped and the
// edge hasn't taken 80 and 443 over yet.
func (w *Watcher) holding() bool {
	return !w.startedAt.IsZero() && !w.handedOff && w.now().Sub(w.startedAt) < HandoffWait
}

// NewWatcher watches src and init's announcement in file.
func NewWatcher(src Source, file string, lg log.Logger) *Watcher {
	if lg == nil {
		lg = log.Nop()
	}
	return &Watcher{src: src, file: file, lg: lg, state: boxstate.Starting, now: time.Now, events: NewHub()}
}

// Events is the stream of the state this watcher keeps.
func (w *Watcher) Events() *Hub { return w.events }

// Push takes a phase accessd pushed, as an answer to a poll, and returns
// the event the streams get.
func (w *Watcher) Push(p Phase) Event {
	if p.Reset {
		w.mu.Lock()
		if w.going {
			w.lg.Info("edgefall: accessd says the reboot or shutdown isn't happening")
		}
		w.going = false
		w.mu.Unlock()
	}
	w.apply(boxstate.Read(w.file), p, nil)
	return w.events.Current()
}

// Poll asks once. An answer sets the state and the claim: on a box with a
// product installed, edgefall holds the edge while the product doesn't
// run, and from a reboot or a shutdown on. Before a product is installed
// nothing answers 80 or 443. No answer (accessd restarting, or drained)
// keeps the last state, unless init has announced a reboot or a shutdown
// meanwhile.
func (w *Watcher) Poll(ctx context.Context) {
	announced := boxstate.Read(w.file)
	p, err := w.src(ctx)
	w.apply(announced, p, err)
}

func (w *Watcher) apply(announced boxstate.State, p Phase, err error) {
	if err == nil && !boxstate.Valid(p.State) {
		err = fmt.Errorf("accessd answered the state %q", p.State)
	}
	w.mu.Lock()
	defer func() {
		st, kind, step, detail := w.state, w.kind, w.step, w.detail
		w.mu.Unlock()
		w.events.Set(st, kind, step, detail)
	}()
	prev, prevClaim := w.state, w.claim
	switch {
	case err == nil:
		s := boxstate.State(p.State)
		if w.going && !boxstate.Going(s) && s != boxstate.Updating {
			s = prev
		}
		w.state = s
		w.going = w.going || boxstate.Going(s) || announced != ""
		w.kind, w.step, w.detail = kindOf(w.state, p.Kind), p.Step, p.Detail
		if w.state != boxstate.Updating {
			w.step, w.detail = "", ""
		}
		w.installed = p.ProductInstalled
		switch {
		case !p.ProductRunning:
			w.stopped, w.startedAt, w.handedOff = true, time.Time{}, false
		case w.stopped:
			w.stopped, w.startedAt = false, w.now()
			w.lg.Info("edgefall: k0s started; holding the edge until the edge asks for it", log.F("wait", HandoffWait.String()))
		}
		w.claim = w.installed && (w.going || !p.ProductRunning || w.holding())
	case announced != "":
		w.going = true
		if prev != boxstate.Updating {
			w.state = announced
		}
		w.claim = w.installed
		w.kind = kindOf(w.state, w.kind)
	}
	if err != nil {
		w.lg.Debug("edgefall: no state from accessd", log.F("error", err.Error()), log.F("announced", string(announced)))
	}
	if w.state != prev {
		w.lg.Info("edgefall: the box state changed", log.F("from", string(prev)), log.F("to", string(w.state)))
	}
	if w.claim != prevClaim {
		w.lg.Info("edgefall: the edge claim changed", log.F("claim", w.claim), log.F("state", string(w.state)))
	}
}

// State is the box state to serve.
func (w *Watcher) State() boxstate.State {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state
}

// Claim is whether edgefall should hold 80 and 443.
func (w *Watcher) Claim() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.claim
}

// kindOf is the stream's kind for a state: a reboot, a shutdown, or for
// an updating box what accessd says it is (an update when it doesn't say);
// none otherwise.
func kindOf(s boxstate.State, said string) string {
	switch s {
	case boxstate.Rebooting:
		return KindReboot
	case boxstate.ShuttingDown:
		return KindShutdown
	case boxstate.Updating:
		if said == KindProductApply {
			return KindProductApply
		}
		return KindUpdate
	}
	return ""
}
