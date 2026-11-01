// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package datamove

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

func runner(f *fixture) *Runner {
	return &Runner{New: func(_ productspec.DataMove, svc Services, progress func(string)) *Move {
		m := *f.m
		m.Services, m.Progress = svc, progress
		return &m
	}}
}

// until asks until the answer isn't "still running".
func until(t *testing.T, r *Runner, svc Services) Status {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := r.Ask(moveSpec(), svc)
		if st.Done || st.Failed {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("still running: %+v", st)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestTheRunnerAnswersAtOnceAndRunsTheMoveBehind(t *testing.T) {
	f := newFixture(t)
	release := make(chan struct{})
	f.e.before["ready old-db"] = func() { <-release }
	r := runner(f)
	st := r.Ask(moveSpec(), f.svc)
	if st.Done || st.Failed || st.Detail == "" {
		t.Fatalf("%+v", st)
	}
	if st := r.Ask(moveSpec(), f.svc); st.Done || st.Failed {
		t.Fatalf("a second ask: %+v", st)
	}
	close(release)
	if st := until(t, r, f.svc); !st.Done {
		t.Fatalf("%+v", st)
	}
	if n := strings.Count(strings.Join(f.e.calls, ","), "ready old-db"); n != 1 {
		t.Fatalf("the move ran %d times", n)
	}
}

func TestTheRunnerHoldsAFailureUntilTheNextApply(t *testing.T) {
	f := newFixture(t)
	f.e.fail["restore:app_one new-db"] = errors.New("boom")
	r := runner(f)
	st := until(t, r, f.svc)
	if !st.Failed || !strings.Contains(st.Detail, "boom") {
		t.Fatalf("%+v", st)
	}
	calls := len(f.e.calls)
	f.e.fail = map[string]error{}
	if st := r.Ask(moveSpec(), f.svc); !st.Failed {
		t.Fatalf("a later ask started over: %+v", st)
	}
	if len(f.e.calls) != calls {
		t.Fatal("a failed move ran again on its own")
	}
	r.Again()
	if st := until(t, r, f.svc); !st.Done {
		t.Fatalf("%+v", st)
	}
}

func TestAMoveCutOffBeforeThisProcessFailsOnTheFirstAsk(t *testing.T) {
	f := newFixture(t)
	if err := f.m.save(&Journal{State: StateRunning, Step: StepDump}); err != nil {
		t.Fatal(err)
	}
	st := until(t, runner(f), f.svc)
	if !st.Failed || !strings.Contains(st.Detail, "cut off") {
		t.Fatalf("%+v", st)
	}
}

func TestTheRunnerSaysAFinishedMoveIsDoneWithoutRunningIt(t *testing.T) {
	f := newFixture(t)
	if err := f.m.save(&Journal{State: StateDone}); err != nil {
		t.Fatal(err)
	}
	if st := runner(f).Ask(moveSpec(), f.svc); !st.Done {
		t.Fatalf("%+v", st)
	}
	if len(f.e.calls) != 0 {
		t.Fatal("ran")
	}
}

func TestUnsettledFollowsTheJournal(t *testing.T) {
	f := newFixture(t)
	r := runner(f)
	if r.Unsettled(moveSpec()) {
		t.Fatal("no move is unsettled")
	}
	if st := until(t, r, f.svc); !st.Done {
		t.Fatalf("%+v", st)
	}
	if !r.Unsettled(moveSpec()) {
		t.Fatal("a switched move is unsettled")
	}
	if err := r.Fail(moveSpec(), "the gateway failed"); err != nil {
		t.Fatal(err)
	}
	if !r.Unsettled(moveSpec()) {
		t.Fatal("a failed move is unsettled")
	}
	g := newFixture(t)
	rg := runner(g)
	if st := until(t, rg, g.svc); !st.Done {
		t.Fatalf("%+v", st)
	}
	if err := rg.Settle(moveSpec()); err != nil {
		t.Fatal(err)
	}
	if rg.Unsettled(moveSpec()) {
		t.Fatal("a settled move is unsettled")
	}
}

func TestAJournalThatWontReadFailsTheMoveWithoutRunningIt(t *testing.T) {
	f := newFixture(t)
	if err := f.m.save(&Journal{}); err != nil {
		t.Fatal(err)
	}
	if err := writeSynced(f.m.Journal, []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	if st := runner(f).Ask(moveSpec(), f.svc); !st.Failed {
		t.Fatalf("%+v", st)
	}
	if len(f.e.calls) != 0 {
		t.Fatal("ran")
	}
}
