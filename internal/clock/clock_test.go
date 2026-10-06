// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package clock_test

import (
	"slices"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
)

func TestFakeRunsDueTimersInOrder(t *testing.T) {
	c := clock.NewFake()
	var got []string
	c.AfterFunc(2*time.Minute, func() { got = append(got, "b") })
	c.AfterFunc(time.Minute, func() { got = append(got, "a") })
	late := c.AfterFunc(10*time.Minute, func() { got = append(got, "late") })
	start := c.Now()
	c.Advance(3 * time.Minute)
	if !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("ran %v", got)
	}
	if c.Now().Sub(start) != 3*time.Minute || c.Mono() != 3*time.Minute {
		t.Fatalf("now moved %v, mono %v", c.Now().Sub(start), c.Mono())
	}
	if !late.Stop() || late.Stop() {
		t.Fatal("Stop should cancel once")
	}
	c.Advance(time.Hour)
	if len(got) != 2 {
		t.Fatal("a stopped timer ran")
	}
}

func TestFakeTimerSetFromATimer(t *testing.T) {
	c := clock.NewFake()
	fired := false
	c.AfterFunc(time.Minute, func() { c.AfterFunc(time.Minute, func() { fired = true }) })
	c.Advance(2 * time.Minute)
	if !fired {
		t.Fatal("a timer scheduled by a timer within the advance didn't run")
	}
}

func TestJumpWallLeavesMono(t *testing.T) {
	c := clock.NewFake()
	before := c.Now()
	c.JumpWall(2 * time.Hour)
	if c.Mono() != 0 || c.Now().Sub(before) != 2*time.Hour {
		t.Fatal("JumpWall moved the monotonic clock or not the wall")
	}
}

func TestRealMonoAdvances(t *testing.T) {
	var c clock.Clock = clock.Real{}
	a := c.Mono()
	done := make(chan struct{})
	c.AfterFunc(time.Millisecond, func() { close(done) })
	<-done
	if c.Mono() <= a {
		t.Fatal("Mono didn't advance")
	}
}
