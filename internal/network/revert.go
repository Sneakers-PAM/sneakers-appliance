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
}

type change struct {
	token string
	prev  Settings
	apply ApplyFunc
	timer clock.Timer
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
	c := &change{token: token, prev: prev, apply: apply}
	c.timer = r.clk.AfterFunc(RevertAfter, func() { r.revert(c) })
	r.pending = c
	r.o.Logger.Info("network: change applied, waiting for confirmation", log.F("seconds", int(RevertAfter.Seconds())))
	return token, nil
}

// Confirm keeps the pending change. A token that isn't the pending one is
// NET_INVALID naming "token"; NET_REVERTED when the change was already
// undone.
func (r *Reverter) Confirm(token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending == nil {
		return codes.New(codes.NetReverted, "there is no change waiting; it was confirmed or reverted already")
	}
	if r.pending.token != token {
		return invalid("token", "that isn't the pending change")
	}
	r.pending.timer.Stop()
	r.pending = nil
	r.o.Logger.Info("network: change confirmed")
	return nil
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
	r.mu.Unlock()
	err := codes.New(codes.NetReverted, "the network change wasn't confirmed within %d seconds and was undone", int(RevertAfter.Seconds()))
	if aerr := c.apply(c.prev); aerr != nil {
		r.o.Logger.Error(aerr, "network: revert failed")
		err = codes.Wrap(codes.NetReverted, aerr)
	}
	r.o.Logger.Warn("network: change reverted", log.F("error", codes.Describe(err)))
	if r.o.OnRevert != nil {
		r.o.OnRevert(c.prev, err)
	}
}

func newToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
