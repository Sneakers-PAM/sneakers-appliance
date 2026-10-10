// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/edgefall"
)

// BoxNotifier takes the box's phase the moment it changes: edgefall's
// push socket on the box, whose answer comes once every open box-state
// stream was sent it.
type BoxNotifier interface {
	Notify(ctx context.Context, p edgefall.Phase) error
}

// notifyTimeout bounds one push: edgefall not answering never holds up an
// update, a reboot or a shutdown for longer.
const notifyTimeout = time.Second

// boxPush coalesces the pushes for step changes: one runs at a time and
// sends the phase as it is when it runs, so the last one always wins.
type boxPush struct {
	mu          sync.Mutex
	busy, again bool
}

// phaseNow is the box's phase as GetPhase answers it, with what an
// updating box is doing: the kind, and the active step's id and words.
func (s *Server) phaseNow(ctx context.Context) edgefall.Phase {
	running := s.productRunning(ctx)
	st := s.boxState(s.Phase(), running)
	p := edgefall.Phase{State: string(st), ProductRunning: running, ProductInstalled: s.slots().Status().Installed != ""}
	if st != boxstate.Updating {
		return p
	}
	s.upgrades.mu.Lock()
	p.Kind = s.upgrades.maintKind
	s.upgrades.mu.Unlock()
	if r := s.progressSnapshot(); r != nil {
		if id := r.active(); id != "" {
			p.Step = id
			if i := r.find(id); i >= 0 {
				p.Detail = r.Steps[i].Label
			}
			if r.Target == targetName(osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT) {
				p.Kind = edgefall.KindProductApply
			}
		}
	}
	if p.Kind == "" {
		p.Kind = edgefall.KindUpdate
	}
	return p
}

// notifyBox pushes the box's phase, or override (a reboot or a shutdown
// about to be asked, or a reset of one that was refused) on top of it, and
// waits for edgefall's answer, so the push happens before whatever the
// caller does next. It never fails the caller: a push edgefall doesn't take
// is logged, and its poll catches up.
func (s *Server) notifyBox(ctx context.Context, override *edgefall.Phase) {
	if s.o.BoxEvents == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), notifyTimeout)
	defer cancel()
	p := s.phaseNow(ctx)
	if override != nil {
		if override.State != "" {
			p.State, p.Kind, p.Step, p.Detail = override.State, "", "", ""
		}
		p.Reset = override.Reset
	}
	started := time.Now()
	if err := s.o.BoxEvents.Notify(ctx, p); err != nil {
		s.o.Logger.Warn("osadmin: edgefall didn't take the box state; its poll catches up", log.F("state", p.State), log.F("error", err.Error()))
		return
	}
	s.o.Logger.Debug("osadmin: box state pushed", log.F("state", p.State), log.F("kind", p.Kind), log.F("step", p.Step), log.F("ms", time.Since(started).Milliseconds()))
}

// boxChanged pushes the phase soon, without waiting: each step change,
// the end of maintenance, the product getting ready.
func (s *Server) boxChanged() {
	if s.o.BoxEvents == nil {
		return
	}
	b := &s.boxPush
	b.mu.Lock()
	if b.busy {
		b.again = true
		b.mu.Unlock()
		return
	}
	b.busy = true
	b.mu.Unlock()
	go func() {
		for {
			s.notifyBox(context.Background(), nil)
			b.mu.Lock()
			if !b.again {
				b.busy = false
				b.mu.Unlock()
				return
			}
			b.again = false
			b.mu.Unlock()
		}
	}()
}
