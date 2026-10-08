// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

// The factory reset's timings (spec 5, Section 2.8.1).
const (
	// ResetDelay runs from the quorum's last approval to the reset; any
	// admin may cancel it until then.
	ResetDelay = 10 * time.Minute
	// ResetPendingLifetime is how long a request waits for its approvals.
	ResetPendingLifetime = 30 * time.Minute
)

// resetRequest is the one factory reset in progress. It lives in memory
// only, so a reboot or a restart of osadmin cancels it.
type resetRequest struct {
	id        string
	startedBy string
	started   time.Time
	expires   time.Time
	members   []string
	required  int
	approvals []string
	runsAt    time.Time
	timer     clock.Timer
}

type resets struct {
	mu  sync.Mutex
	cur *resetRequest
}

func (r *resetRequest) wire() *osadminv1.FactoryReset {
	w := &osadminv1.FactoryReset{
		Id: r.id, StartedBy: r.startedBy, Started: timestamppb.New(r.started), Expires: timestamppb.New(r.expires),
		Members: slices.Clone(r.members), Required: int32(min(r.required, 1<<30)), Approvals: slices.Clone(r.approvals), // #nosec G115 -- clamped
		State: osadminv1.FactoryResetState_FACTORY_RESET_STATE_PENDING,
	}
	if !r.runsAt.IsZero() {
		w.State, w.RunsAt = osadminv1.FactoryResetState_FACTORY_RESET_STATE_COUNTDOWN, timestamppb.New(r.runsAt)
	}
	return w
}

// FactoryReset returns the reset in progress, or nil.
func (s *Server) FactoryReset() *osadminv1.FactoryReset {
	s.resets.mu.Lock()
	defer s.resets.mu.Unlock()
	if s.resets.cur == nil {
		return nil
	}
	return s.resets.cur.wire()
}

// startReset opens a request. The starter's approval counts once, when
// they are on the roster.
func (s *Server) startReset(actor string) (*osadminv1.FactoryReset, error) {
	q := s.o.Access.Read().EffectiveQuorum()
	if !q.Available() {
		return nil, codes.New(codes.ResetUnavailable, "a factory reset needs a quorum of at least two admins; with one admin, delete and re-create or re-flash the box instead")
	}
	s.resets.mu.Lock()
	defer s.resets.mu.Unlock()
	if s.resets.cur != nil {
		return nil, codes.New(codes.ResetUnavailable, "a factory reset is already in progress")
	}
	now := s.o.Clock.Now()
	r := &resetRequest{id: "R-" + strings.ToUpper(weblogin.Secret()[:6]), startedBy: actor, started: now, expires: now.Add(ResetPendingLifetime), members: q.Members, required: q.Required}
	if slices.Contains(q.Members, actor) {
		r.approvals = []string{actor}
	}
	r.timer = s.o.Clock.AfterFunc(ResetPendingLifetime, func() { s.expireReset(r) })
	s.resets.cur = r
	s.o.Logger.Info("osadmin: factory reset requested", log.F("id", r.id), log.F("by", actor), log.F("required", r.required), log.F("members", len(r.members)))
	return r.wire(), nil
}

// approveReset adds a roster member's approval. The last one needed starts
// the delay.
func (s *Server) approveReset(id, actor string) (*osadminv1.FactoryReset, error) {
	s.resets.mu.Lock()
	defer s.resets.mu.Unlock()
	r := s.resets.cur
	if r == nil || r.id != id {
		return nil, codes.New(codes.ResetCancelled, "there is no factory reset %q in progress", id)
	}
	if !slices.Contains(r.members, actor) {
		return nil, codes.New(codes.ResetApproved, "%s isn't on the quorum roster", actor)
	}
	if slices.Contains(r.approvals, actor) {
		return nil, codes.New(codes.ResetApproved, "%s's approval is already counted; another roster member must approve", actor)
	}
	if !r.runsAt.IsZero() {
		return nil, codes.New(codes.ResetApproved, "the quorum has already approved; the reset is counting down")
	}
	if len(r.approvals)+1 >= r.required {
		// Init checks the quorum against the roster itself and counts its
		// own delay; without its arming the countdown doesn't start.
		approvals := append(slices.Clone(r.approvals), actor)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := s.o.Power.ArmFactoryReset(ctx, connect.NewRequest(&initv1.ArmFactoryResetRequest{Id: r.id, StartedBy: r.startedBy, Approvals: approvals}))
		cancel()
		if err != nil {
			s.o.Logger.Error(err, "osadmin: init refused to arm the factory reset", log.F("id", r.id))
			return nil, err
		}
	}
	r.approvals = append(r.approvals, actor)
	if len(r.approvals) >= r.required {
		r.timer.Stop()
		r.runsAt = s.o.Clock.Now().Add(ResetDelay)
		r.timer = s.o.Clock.AfterFunc(ResetDelay, func() { s.runReset(r) })
		s.o.Logger.Warn("osadmin: factory reset approved by its quorum; counting down", log.F("id", r.id), log.F("runsAt", r.runsAt))
	}
	return r.wire(), nil
}

// cancelReset stops the request or its countdown.
func (s *Server) cancelReset(id string) error {
	s.resets.mu.Lock()
	defer s.resets.mu.Unlock()
	r := s.resets.cur
	if r == nil || (id != "" && r.id != id) {
		return codes.New(codes.ResetCancelled, "there is no factory reset %q in progress", id)
	}
	r.timer.Stop()
	s.resets.cur = nil
	s.o.Logger.Warn("osadmin: factory reset cancelled", log.F("id", r.id))
	if !r.runsAt.IsZero() {
		s.disarm(r.id)
	}
	return nil
}

// disarm tells init to forget an armed reset. osadmin has already dropped
// it, so it never asks init to run it; init forgets it on its own when it
// expires.
func (s *Server) disarm(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := s.o.Power.CancelFactoryReset(ctx, connect.NewRequest(&initv1.CancelFactoryResetRequest{Id: id})); err != nil {
		s.o.Logger.Error(err, "osadmin: init didn't take the cancel; it forgets the reset when it expires", log.F("id", id))
	}
}

func (s *Server) expireReset(r *resetRequest) {
	s.resets.mu.Lock()
	if s.resets.cur != r || !r.runsAt.IsZero() {
		s.resets.mu.Unlock()
		return
	}
	s.resets.cur = nil
	s.resets.mu.Unlock()
	s.write(osaudit.Entry{Actor: "osadmin", Action: "power.factory-reset.expire", Target: "factory reset", Detail: map[string]string{"reset": r.id}}, codes.New(codes.ResetCancelled, "the quorum didn't approve within %d minutes", int(ResetPendingLifetime.Minutes())))
}

func (s *Server) runReset(r *resetRequest) {
	s.resets.mu.Lock()
	if s.resets.cur != r {
		s.resets.mu.Unlock()
		return
	}
	s.resets.cur = nil
	s.resets.mu.Unlock()
	s.o.Logger.Warn("osadmin: factory reset running", log.F("id", r.id), log.F("startedBy", r.startedBy), log.F("approvals", strings.Join(r.approvals, ",")))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := s.o.Power.FactoryReset(ctx, connect.NewRequest(&initv1.FactoryResetRequest{Id: r.id, StartedBy: r.startedBy, Approvals: r.approvals}))
	s.write(osaudit.Entry{Actor: r.startedBy, Action: "power.factory-reset.run", Target: "factory reset", Detail: map[string]string{"reset": r.id, "approvals": strings.Join(r.approvals, ",")}}, err)
	if err != nil {
		s.o.Logger.Error(err, "osadmin: factory reset failed", log.F("id", r.id))
	}
}
