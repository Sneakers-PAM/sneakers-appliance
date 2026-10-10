// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package edgefall_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
)

type pollRun struct {
	Running struct {
		First int     `json:"first"`
		Gaps  []int64 `json:"gaps"`
		Other []int64 `json:"other"`
	} `json:"running"`
	Rebooting   struct{ Gaps []int64 } `json:"rebooting"`
	Unreachable struct{ Gaps []int64 } `json:"unreachable"`
	Kick        struct {
		Header    []int64 `json:"header"`
		FastWhile []int64 `json:"fastWhile"`
		Later     []int64 `json:"later"`
		Error     []int64 `json:"error"`
	} `json:"kick"`
	Slow struct {
		Aborted     int `json:"aborted"`
		MaxInFlight int `json:"maxInFlight"`
		Asks        int `json:"asks"`
	} `json:"slow"`
	Thaw struct {
		Overlay int `json:"overlay"`
	} `json:"thaw"`
	Events struct {
		AsksUp        int `json:"asksUp"`
		OverlayBefore int `json:"overlayBefore"`
		OverlayNow    int `json:"overlayNow"`
		Streams       int `json:"streams"`
	} `json:"events"`
	DropUpdating struct {
		Retries []int64 `json:"retries"`
		Overlay int     `json:"overlay"`
		Reloads int     `json:"reloads"`
	} `json:"dropUpdating"`
	DropRunning struct {
		Retries []int64 `json:"retries"`
		Asks    int     `json:"asks"`
		Overlay int     `json:"overlay"`
	} `json:"dropRunning"`
	Refused struct {
		Gaps    []int64 `json:"gaps"`
		Overlay int     `json:"overlay"`
	} `json:"refused"`
	Hidden struct {
		WhileHidden int     `json:"whileHidden"`
		OnShow      []int64 `json:"onShow"`
	} `json:"hidden"`
}

// runPoller runs the served poll.js on testdata/pollclock.js's fake clock
// (node, which CI's runners carry).
func runPoller(t *testing.T) pollRun {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node isn't installed")
	}
	_, js := get(t, serve(t, boxstate.Running).URL+"/_box/poll.js")
	file := filepath.Join(t.TempDir(), "poll.js")
	if err := os.WriteFile(file, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "testdata/pollclock.js", file).Output() // #nosec G204 -- the test's own files
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("pollclock: %v\n%s", err, ee.Stderr)
		}
		t.Fatal(err)
	}
	var r pollRun
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	return r
}

func within(t *testing.T, what string, gaps []int64, lo, hi int64) {
	t.Helper()
	if len(gaps) == 0 {
		t.Fatalf("%s: no asks", what)
	}
	for _, g := range gaps {
		if g < lo || g > hi {
			t.Fatalf("%s: a gap of %d ms, want %d to %d: %v", what, g, lo, hi, gaps[:min(len(gaps), 12)])
		}
	}
}

// While the box runs, the poller asks about every 45 seconds, each tab at
// its own jittered times; while it isn't running, or can't be reached,
// every second.
func TestThePollerAsksSlowlyWhileTheBoxRuns(t *testing.T) {
	r := runPoller(t)
	if r.Running.First != 0 {
		t.Fatalf("the first ask came at %d ms, want at load", r.Running.First)
	}
	within(t, "running", r.Running.Gaps, 37500, 52500)
	within(t, "running, another tab", r.Running.Other, 37500, 52500)
	if len(r.Running.Gaps) < 10 || len(r.Running.Gaps) > 16 {
		t.Fatalf("running: %d asks in 10 minutes", len(r.Running.Gaps)+1)
	}
	same := true
	for i := range min(len(r.Running.Gaps), len(r.Running.Other)) {
		same = same && r.Running.Gaps[i] == r.Running.Other[i]
	}
	if same {
		t.Fatalf("two tabs ask in step: %v", r.Running.Gaps)
	}
	within(t, "rebooting", r.Rebooting.Gaps, 1000, 1000)
	if len(r.Rebooting.Gaps) < 25 {
		t.Fatalf("rebooting: %d asks in 30 s", len(r.Rebooting.Gaps)+1)
	}
	within(t, "unreachable", r.Unreachable.Gaps, 1000, 1000)
}

// A page request that answers with Sneakers-Box-State, or fails, makes the
// poller ask at once and keep asking every second for a while; then it
// slows down again.
func TestThePollerAsksAtOnceAfterAPageRequestFails(t *testing.T) {
	r := runPoller(t)
	if len(r.Kick.Header) == 0 || r.Kick.Header[0] != 0 {
		t.Fatalf("after a Sneakers-Box-State answer the poller asked at %v ms", r.Kick.Header)
	}
	within(t, "after the header", r.Kick.FastWhile, 1000, 1000)
	within(t, "later", r.Kick.Later, 37500, 52500)
	if len(r.Kick.Error) == 0 || r.Kick.Error[0] != 0 {
		t.Fatalf("after a network error the poller asked at %v ms", r.Kick.Error)
	}
}

// A hidden tab doesn't ask; shown again, it asks at once.
func TestThePollerWaitsWhileTheTabIsHidden(t *testing.T) {
	r := runPoller(t)
	if r.Hidden.WhileHidden != 0 {
		t.Fatalf("a hidden tab asked %d times", r.Hidden.WhileHidden)
	}
	if len(r.Hidden.OnShow) != 1 || r.Hidden.OnShow[0] != 0 {
		t.Fatalf("shown again, the tab asked at %v ms", r.Hidden.OnShow)
	}
}

// A box that takes 2.5 seconds to answer isn't given up on, and the
// poller never has two asks out at once, so slow answers don't pile up
// into timeouts.
func TestThePollerWaitsForASlowAnswerAndNeverOverlaps(t *testing.T) {
	r := runPoller(t)
	if r.Slow.Aborted != 0 || r.Slow.MaxInFlight != 1 || r.Slow.Asks < 10 {
		t.Fatalf("slow box: %+v", r.Slow)
	}
	if r.Thaw.Overlay != 0 {
		t.Fatalf("an ask that failed while the tab was hidden laid the overlay over the page")
	}
}

// With the state events, the one ask at load is all while the stream is
// up, and an event lays the box-state page over at once, from one stream.
func TestTheClientFollowsTheStateEvents(t *testing.T) {
	r := runPoller(t).Events
	if r.AsksUp != 1 || r.Streams != 1 {
		t.Fatalf("with the stream up for 10 minutes: %d asks, %d streams", r.AsksUp, r.Streams)
	}
	if r.OverlayBefore != 0 || r.OverlayNow != 1 {
		t.Fatalf("an updating event didn't lay the page over at once: %+v", r)
	}
}

// A stream that drops while the box updates keeps the page up and is
// tried again after 1, 2, 4, 8 and then 10 seconds; once it opens on a
// running box, the page reloads.
func TestADroppedStreamWhileUpdatingBacksOff(t *testing.T) {
	r := runPoller(t).DropUpdating
	want := []int64{1000, 3000, 7000, 15000, 25000, 35000}
	if len(r.Retries) < len(want) {
		t.Fatalf("retries at %v ms", r.Retries)
	}
	for i, w := range want {
		if r.Retries[i] != w {
			t.Fatalf("retries at %v ms, want %v", r.Retries, want)
		}
	}
	if r.Overlay != 1 || r.Reloads != 1 {
		t.Fatalf("overlay %d, reloads %d", r.Overlay, r.Reloads)
	}
}

// A stream that drops while the box runs is tried again at once; after
// three failures one ask of /_box/state decides, and a running answer
// says nothing to the page.
func TestADroppedStreamWhileRunningRetriesAtOnce(t *testing.T) {
	r := runPoller(t).DropRunning
	if len(r.Retries) != 3 || r.Retries[0] != 0 || r.Asks != 1 || r.Overlay != 0 {
		t.Fatalf("%+v", r)
	}
}

// While the stream can't open, a slow poll every 30 to 60 seconds is the
// fallback.
func TestTheFallbackPollIsSlow(t *testing.T) {
	r := runPoller(t).Refused
	if len(r.Gaps) < 3 || r.Overlay != 0 {
		t.Fatalf("%+v", r)
	}
	within(t, "fallback", r.Gaps[1:], 30000, 60000)
}
