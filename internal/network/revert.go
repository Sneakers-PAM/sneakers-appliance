// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// RevertAfter is how long a change waits for its confirmation.
const RevertAfter = 120 * time.Second

// ApplyFunc applies settings to the box.
type ApplyFunc func(Settings) error

// RevertOptions tune a Reverter.
type RevertOptions struct {
	// OnRevert is told about every change undone for lack of a confirmation,
	// with the NET_REVERTED error (and the error of re-applying the previous
	// settings, if that failed too).
	OnRevert func(prev Settings, err error)
	Logger   log.Logger
}

// Reverter applies one change at a time and undoes it unless Confirm comes
// within RevertAfter, so a change that cuts the admin off heals itself.
type Reverter struct {
	clk clock.Clock
	o   RevertOptions

	mu      sync.Mutex
	pending *change
	last    *Outcome
}

type change struct {
	id       string
	token    string
	deadline time.Time
	prev     Settings
	apply    ApplyFunc
	timer    clock.Timer
}

// Pending is the change that waits for its confirmation.
type Pending struct {
	// ID names the change in logs and the audit; Token is the secret
	// Confirm takes.
	ID, Token string
	Deadline  time.Time
}

// Left is how long the change still waits at now, never below zero.
func (p Pending) Left(now time.Time) time.Duration {
	return max(p.Deadline.Sub(now), 0)
}

// Outcome is how a change ended.
type Outcome struct {
	ID       string
	Reverted bool
	// AtStart: the change was undone when netd started, because the box
	// restarted inside its window.
	AtStart bool
	At      time.Time
}

// NewReverter returns a reverter on clk.
func NewReverter(clk clock.Clock, o ...RevertOptions) *Reverter {
	r := &Reverter{clk: clk}
	if len(o) > 0 {
		r.o = o[0]
	}
	if r.o.Logger == nil {
		r.o.Logger = log.Nop()
	}
	return r
}

// Apply validates next, applies it and starts the revert timer. It returns
// the token Confirm takes. A second Apply while one is pending is refused
// with NET_INVALID naming "pending". When applying next fails, prev is
// applied again and the error returned.
func (r *Reverter) Apply(prev, next Settings, apply ApplyFunc) (string, error) {
	if err := Validate(next); err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending != nil {
		return "", invalid("pending", "a network change is waiting for its confirmation; confirm it or let it revert first")
	}
	if err := apply(next); err != nil {
		r.o.Logger.Error(err, "network: apply failed, restoring the previous settings")
		if rerr := apply(prev); rerr != nil {
			r.o.Logger.Error(rerr, "network: restoring the previous settings failed")
		}
		return "", err
	}
	token := newToken()
	c := &change{id: newToken()[:12], token: token, deadline: r.clk.Now().Add(RevertAfter), prev: prev, apply: apply}
	c.timer = r.clk.AfterFunc(RevertAfter, func() { r.revert(c) })
	r.pending = c
	r.o.Logger.Info("network: change applied, waiting for confirmation", log.F("change", c.id), log.F("seconds", int(RevertAfter.Seconds())))
	return token, nil
}

// Confirm keeps the pending change. A token that isn't the pending one is
// NET_INVALID naming "token"; NET_REVERTED when the change was already
// undone.
//
// keep, when given, runs once the token checks out and before the change
// counts as kept: when it fails (the undo file can't be removed, say) the
// change stays pending and its error is returned.
func (r *Reverter) Confirm(token string, keep ...func() error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		return codes.New(codes.NetReverted, "there is no change waiting; it was confirmed or reverted already")
	}
	if r.pending.token != token {
		return invalid("token", "that isn't the pending change")
	}
	for _, k := range keep {
		if err := k(); err != nil {
			r.o.Logger.Error(err, "network: the change can't be kept; it stays pending", log.F("change", r.pending.id))
			return err
		}
	}
	r.pending.timer.Stop()
	r.last = &Outcome{ID: r.pending.id, At: r.clk.Now()}
	r.o.Logger.Info("network: change confirmed", log.F("change", r.pending.id))
	r.pending = nil
	return nil
}

// PendingChange returns the change that waits for its confirmation.
func (r *Reverter) PendingChange() (Pending, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		return Pending{}, false
	}
	return Pending{ID: r.pending.id, Token: r.pending.token, Deadline: r.pending.deadline}, true
}

// RevertedAtStart records that a change left unconfirmed when the box
// stopped was undone at start, so Last reports it.
func (r *Reverter) RevertedAtStart() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last = &Outcome{ID: "start-" + newToken()[:6], Reverted: true, AtStart: true, At: r.clk.Now()}
}

// Last returns how the most recent change ended.
func (r *Reverter) Last() (Outcome, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == nil {
		return Outcome{}, false
	}
	return *r.last, true
}

// Pending reports whether a change waits for its confirmation.
func (r *Reverter) Pending() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pending != nil
}

func (r *Reverter) revert(c *change) {
	r.mu.Lock()
	if r.pending != c {
		r.mu.Unlock()
		return
	}
	r.pending = nil
	r.last = &Outcome{ID: c.id, Reverted: true, At: r.clk.Now()}
	r.mu.Unlock()
	err := codes.New(codes.NetReverted, "the network change wasn't confirmed within %d seconds and was undone", int(RevertAfter.Seconds()))
	if aerr := c.apply(c.prev); aerr != nil {
		r.o.Logger.Error(aerr, "network: revert failed")
		err = codes.Wrap(codes.NetReverted, aerr)
	}
	r.o.Logger.Error(err, "network: the change wasn't confirmed and was reverted", log.F("change", c.id))
	if r.o.OnRevert != nil {
		r.o.OnRevert(c.prev, err)
	}
}

func newToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
