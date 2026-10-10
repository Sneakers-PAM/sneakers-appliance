// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package diskguard

import (
	"context"
	"strconv"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// The cleanup's triggers.
const (
	TriggerTimer = "timer"
	TriggerAlert = "alert"
	TriggerAdmin = "admin"
)

// ActionCleanup is the audit entry every cleanup run writes.
const ActionCleanup = "disk.cleanup.run"

// guardActor is the actor of what the guard does by itself.
const guardActor = "disk-guard"

// Env is what a step works with.
type Env struct {
	Now    time.Time
	Safety Safety
	Logger log.Logger
	// State is the state volume's use as the run started.
	State Usage
}

// Result is what a step did: the bytes it freed and, when it has
// something to say (a check-only step, a skip), a note.
type Result struct {
	Freed int64
	Note  string
}

// Step is one category of the cleanup.
type Step interface {
	Category() string
	Clean(ctx context.Context, env Env) (Result, error)
}

// CategoryResult is one step's part of a run.
type CategoryResult struct {
	Category string
	Freed    int64
	Note     string
	Error    string
}

// Run is one cleanup run.
type Run struct {
	At         time.Time
	Trigger    string
	Actor      string
	Categories []CategoryResult
	Freed      int64
}

// Cleaner runs the steps in order, one run at a time, and audits each run
// with what every category freed.
type Cleaner struct {
	Steps  []Step
	Safety Safety
	Audit  osaudit.Appender
	// StatePath is the state volume, read before a run for the steps that
	// size themselves from it.
	StatePath string
	Statfs    func(string) (Usage, error)
	Now       func() time.Time
	Logger    log.Logger

	mu   sync.Mutex
	last *Run
}

func (c *Cleaner) logger() log.Logger {
	if c.Logger == nil {
		return log.Nop()
	}
	return c.Logger
}

// Run runs every step and audits the run. actor is the admin who asked,
// or "" for the guard itself. A failed step is recorded and the rest
// still run.
func (c *Cleaner) Run(ctx context.Context, trigger, actor string) Run {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	statfs := c.Statfs
	if statfs == nil {
		statfs = Statfs
	}
	env := Env{Now: now(), Safety: c.Safety, Logger: c.logger()}
	if c.StatePath != "" {
		if u, err := statfs(c.StatePath); err == nil {
			env.State = u
		} else {
			c.logger().Warn("diskguard: the state volume doesn't read before a cleanup", log.F("error", err.Error()))
		}
	}
	if actor == "" {
		actor = guardActor
	}
	run := Run{At: env.Now, Trigger: trigger, Actor: actor}
	c.logger().Info("diskguard: cleanup starts", log.F("trigger", trigger), log.F("by", actor))
	for _, st := range c.Steps {
		if ctx.Err() != nil {
			run.Categories = append(run.Categories, CategoryResult{Category: st.Category(), Error: ctx.Err().Error()})
			continue
		}
		start := time.Now()
		res, err := st.Clean(ctx, env)
		cr := CategoryResult{Category: st.Category(), Freed: max(res.Freed, 0), Note: res.Note}
		if err != nil {
			cr.Error = err.Error()
			c.logger().Error(err, "diskguard: a cleanup step failed", log.F("category", cr.Category))
		}
		c.logger().Info("diskguard: cleanup step done", log.F("category", cr.Category), log.F("freed", cr.Freed), log.F("note", cr.Note), log.F("took", time.Since(start).String()))
		run.Categories = append(run.Categories, cr)
		run.Freed += cr.Freed
	}
	c.audit(run)
	c.last = &run
	c.logger().Info("diskguard: cleanup done", log.F("trigger", trigger), log.F("freed", run.Freed))
	return run
}

// Last is the newest run, or nil before the first.
func (c *Cleaner) Last() *Run {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		return nil
	}
	r := *c.last
	return &r
}

func (c *Cleaner) audit(run Run) {
	if c.Audit == nil {
		return
	}
	d := map[string]string{"trigger": run.Trigger, "freed": strconv.FormatInt(run.Freed, 10)}
	outcome := "ok"
	for _, cr := range run.Categories {
		d["freed."+cr.Category] = strconv.FormatInt(cr.Freed, 10)
		if cr.Note != "" {
			d["note."+cr.Category] = cr.Note
		}
		if cr.Error != "" {
			d["error."+cr.Category] = cr.Error
			outcome = "partial"
		}
	}
	if err := c.Audit.Append(osaudit.Entry{Time: run.At, Actor: run.Actor, Action: ActionCleanup, Target: "disk", Outcome: outcome, Detail: d}); err != nil {
		c.logger().Error(err, "diskguard: the cleanup's audit entry wasn't written")
	}
}
