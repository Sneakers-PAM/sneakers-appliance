// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package clock is the time source the access and network code takes, so
// timeouts, expiries and clock steps test against a fake instead of sleeping.
package clock

import (
	"sort"
	"sync"
	"time"
)

// Clock tells the time and runs timers.
type Clock interface {
	// Now is the wall clock, which NTP may step.
	Now() time.Time
	// Mono is a monotonic reading: only differences between two readings
	// mean anything, and a wall clock step doesn't move it.
	Mono() time.Duration
	// AfterFunc runs f in its own goroutine once d has passed.
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer is a pending AfterFunc.
type Timer interface {
	// Stop cancels the timer; it reports false when f already ran or was
	// stopped.
	Stop() bool
}

// Real is the system clock.
type Real struct{}

var start = time.Now()

// Now returns time.Now.
func (Real) Now() time.Time { return time.Now() }

// Mono returns the time since the process started, on the monotonic clock.
func (Real) Mono() time.Duration { return time.Since(start) }

// AfterFunc wraps time.AfterFunc.
func (Real) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }

// Fake is a clock that moves only when told to. Timers due by an Advance run
// before Advance returns, in due order, on the caller's goroutine.
type Fake struct {
	mu     sync.Mutex
	wall   time.Time
	mono   time.Duration
	timers []*fakeTimer
}

// NewFake returns a fake clock at a fixed wall time.
func NewFake() *Fake {
	return &Fake{wall: time.Date(2026, 10, 5, 14, 0, 0, 0, time.UTC)}
}

// Now returns the fake wall time.
func (c *Fake) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wall
}

// Mono returns the fake monotonic reading.
func (c *Fake) Mono() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mono
}

// AfterFunc schedules f on the fake timeline.
func (c *Fake) AfterFunc(d time.Duration, f func()) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, due: c.mono + d, f: f}
	c.timers = append(c.timers, t)
	return t
}

// Advance moves both clocks forward by d and runs every timer that falls due.
func (c *Fake) Advance(d time.Duration) {
	c.mu.Lock()
	target := c.mono + d
	c.mu.Unlock()
	for {
		c.mu.Lock()
		sort.SliceStable(c.timers, func(i, j int) bool { return c.timers[i].due < c.timers[j].due })
		if len(c.timers) == 0 || c.timers[0].due > target {
			c.wall = c.wall.Add(target - c.mono)
			c.mono = target
			c.mu.Unlock()
			return
		}
		t := c.timers[0]
		c.timers = c.timers[1:]
		c.wall = c.wall.Add(t.due - c.mono)
		c.mono = t.due
		c.mu.Unlock()
		t.f()
	}
}

// JumpWall steps only the wall clock, as an NTP correction does.
func (c *Fake) JumpWall(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(d)
}

type fakeTimer struct {
	c   *Fake
	due time.Duration
	f   func()
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	for i, o := range t.c.timers {
		if o == t {
			t.c.timers = append(t.c.timers[:i], t.c.timers[i+1:]...)
			return true
		}
	}
	return false
}
