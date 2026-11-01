// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package datamove

import (
	"context"
	"sync"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// Status is where the box's move stands, as the phase loop asks it.
type Status struct {
	// Done lets the later phases start.
	Done bool
	// Failed: the move can't go on, and the box goes back. Detail says why.
	Failed bool
	Detail string
}

// Runner runs the box's move behind the phase loop, which asks every few
// seconds and must get an answer at once. It's one per process: the move's
// state outlives the process in its journal.
type Runner struct {
	// New builds the move the slot declares.
	New    func(spec productspec.DataMove, svc Services, progress func(string)) *Move
	Logger log.Logger

	mu      sync.Mutex
	running bool
	detail  string
	failure string
}

// Ask answers where the move stands, and starts it when it's due. A move
// that failed stays failed until Again, so one failure can't turn into a
// loop of moves while the box goes back.
func (r *Runner) Ask(spec productspec.DataMove, svc Services) Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		return Status{Detail: r.detail}
	}
	if r.failure != "" {
		return Status{Failed: true, Detail: r.failure}
	}
	m := r.New(spec, svc, r.progress)
	j, err := m.Read()
	if err != nil {
		r.failure = err.Error()
		return Status{Failed: true, Detail: r.failure}
	}
	if j.State == StateSwitched || j.State == StateDone {
		return Status{Done: true}
	}
	r.running, r.detail = true, "Starting the move"
	go func() {
		// The move runs on past any one ask; its own timeout bounds it.
		err := m.Run(context.Background())
		r.mu.Lock()
		defer r.mu.Unlock()
		r.running = false
		if err != nil {
			r.failure = err.Error()
		}
	}()
	return Status{Detail: r.detail}
}

func (r *Runner) progress(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.detail = s
}

// Unsettled is whether the box isn't yet proven on the target: a move that
// started and hasn't settled, which a failure of the product goes back from.
func (r *Runner) Unsettled(spec productspec.DataMove) bool {
	j, err := r.New(spec, nil, nil).Read()
	if err != nil {
		return true
	}
	return j.State != "" && j.State != StateDone
}

// Settle records the box healthy on the target.
func (r *Runner) Settle(spec productspec.DataMove) error {
	return r.New(spec, nil, nil).Settle()
}

// Fail records that the box goes back from the move.
func (r *Runner) Fail(spec productspec.DataMove, why string) error {
	return r.New(spec, nil, nil).Fail(why)
}

// Again lets a new apply try a failed move again.
func (r *Runner) Again() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failure = ""
}
