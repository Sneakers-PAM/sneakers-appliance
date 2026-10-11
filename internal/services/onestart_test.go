// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package services_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/services"
)

// prepRunner is a runner whose pre-start can be held open, and which counts
// how many pre-starts and processes of the service run at once: k0s's
// pre-start (k0s-interim prepare) isn't safe to run twice at a time.
type prepRunner struct {
	mu              sync.Mutex
	hold            chan struct{}
	inPrep, maxPrep int
	preps, starts   int
	live, maxLive   int
	procs           []*fakeProc
	entered         chan struct{}
	failPrep        bool
}

func newPrepRunner() *prepRunner { return &prepRunner{entered: make(chan struct{}, 64)} }

func (r *prepRunner) Run(_ context.Context, _ []string) error {
	r.mu.Lock()
	r.preps++
	r.inPrep++
	r.maxPrep = max(r.maxPrep, r.inPrep)
	hold, fail := r.hold, r.failPrep
	r.mu.Unlock()
	r.entered <- struct{}{}
	if hold != nil {
		<-hold
	}
	r.mu.Lock()
	r.inPrep--
	r.mu.Unlock()
	if fail {
		return errors.New("exit status 1")
	}
	return nil
}

func (r *prepRunner) Start([]string) (services.Process, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.starts++
	r.live++
	r.maxLive = max(r.maxLive, r.live)
	p := &fakeProc{exit: make(chan error, 1)}
	r.procs = append(r.procs, p)
	return &countedProc{fakeProc: p, r: r}, nil
}

func (r *prepRunner) Exists(string) bool { return true }

func (r *prepRunner) last() *fakeProc {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.procs[len(r.procs)-1]
}

func (r *prepRunner) counts() (preps, maxPrep, starts, maxLive int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.preps, r.maxPrep, r.starts, r.maxLive
}

type countedProc struct {
	*fakeProc
	r    *prepRunner
	once sync.Once
}

func (p *countedProc) Wait() error {
	err := p.fakeProc.Wait()
	p.once.Do(func() {
		p.r.mu.Lock()
		p.r.live--
		p.r.mu.Unlock()
	})
	return err
}

func (p *countedProc) Signal(sig os.Signal) error { return p.fakeProc.Signal(sig) }

// productTable is k0s as the box runs it: gated on its start-when paths,
// restarted always, with a pre-start.
func productTable(t *testing.T) services.Table {
	t.Helper()
	tbl, err := services.Load(fstest.MapFS{
		"d/k0s.yaml": {Data: []byte("exec: /bin/sh\nargs: [k0s-interim, run]\nphases: [normal]\nrestart: always\nstart-when: [" + setupDone + ", " + installed + "]\npre-start: [/bin/sh, k0s-interim, prepare]\n")},
	}, "d")
	if err != nil {
		t.Fatal(err)
	}
	return tbl
}

func waitEntered(t *testing.T, r *prepRunner) {
	t.Helper()
	select {
	case <-r.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the pre-start didn't run")
	}
}

// A Start while the service's pre-start runs waits for that start and
// answers its outcome; it never runs a second pre-start beside it.
func TestAStartDuringAPreStartJoinsIt(t *testing.T) {
	r := newPrepRunner()
	r.hold = make(chan struct{})
	s := services.NewSupervisor(r, productTable(t), opts())
	ctx := context.Background()
	entered := make(chan error, 1)
	go func() { entered <- s.EnterPhase(ctx, phase.Normal) }()
	waitEntered(t, r)
	joined := make(chan error, 1)
	go func() { joined <- s.Start(ctx, "k0s") }()
	select {
	case err := <-joined:
		t.Fatalf("Start answered (%v) before the pre-start in flight ended", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(r.hold)
	if err := <-joined; err != nil {
		t.Fatal(err)
	}
	if err := <-entered; err != nil {
		t.Fatal(err)
	}
	preps, maxPrep, starts, maxLive := r.counts()
	if preps != 1 || maxPrep != 1 || starts != 1 || maxLive != 1 {
		t.Fatalf("preps %d (at once %d), starts %d (at once %d); want one of each", preps, maxPrep, starts, maxLive)
	}
}

// A joined Start answers the pre-start's failure too.
func TestAStartDuringAFailingPreStartAnswersTheFailure(t *testing.T) {
	r := newPrepRunner()
	r.hold, r.failPrep = make(chan struct{}), true
	tbl := productTable(t)
	tbl["k0s"].Restart = services.RestartNever
	s := services.NewSupervisor(r, tbl, opts())
	ctx := context.Background()
	go func() { _ = s.EnterPhase(ctx, phase.Normal) }()
	waitEntered(t, r)
	joined := make(chan error, 1)
	go func() { joined <- s.Start(ctx, "k0s") }()
	time.Sleep(50 * time.Millisecond)
	close(r.hold)
	if err := <-joined; err == nil {
		t.Fatal("Start joined a failed pre-start and answered no error")
	}
	if preps, _, _, _ := r.counts(); preps != 1 {
		t.Fatalf("%d pre-starts, want 1", preps)
	}
}

// After the product crashes its restart waits out a backoff; a product
// apply (Stop, then Start) in that window starts it once. The pending
// relaunch is cancelled: it never runs a second pre-start beside the
// Start's, which made k0s-interim prepare fail with exit status 1.
func TestAnApplyDuringARestartBackoffStartsOnce(t *testing.T) {
	for _, stopFirst := range []bool{true, false} {
		r := newPrepRunner()
		o := opts()
		o.Backoff, o.MaxBackoff = 100*time.Millisecond, 100*time.Millisecond
		s := services.NewSupervisor(r, productTable(t), o)
		ctx := context.Background()
		if err := s.EnterPhase(ctx, phase.Normal); err != nil {
			t.Fatal(err)
		}
		waitEntered(t, r)
		eventually(t, "k0s to run", func() bool { return s.Running("k0s") })
		r.mu.Lock()
		r.hold = make(chan struct{})
		r.mu.Unlock()
		r.last().crash()
		eventually(t, "k0s to exit", func() bool { return !s.Running("k0s") })
		if stopFirst {
			if err := s.Stop("k0s"); err != nil {
				t.Fatal(err)
			}
		}
		started := make(chan error, 1)
		go func() { started <- s.Start(ctx, "k0s") }()
		waitEntered(t, r)
		// Past the backoff: the pending relaunch would run now.
		time.Sleep(250 * time.Millisecond)
		close(r.hold)
		if err := <-started; err != nil {
			t.Fatal(err)
		}
		time.Sleep(250 * time.Millisecond)
		preps, maxPrep, starts, maxLive := r.counts()
		if preps != 2 || maxPrep != 1 || starts != 2 || maxLive != 1 {
			t.Errorf("stop first %v: preps %d (at once %d), starts %d (at once %d); want 2 preps and 2 starts, one at a time", stopFirst, preps, maxPrep, starts, maxLive)
		}
		_ = s.Stop("k0s")
	}
}

// A product apply's Stop and Start, over and over: the stopped process is
// never restarted by its exit, whenever the Start lands, so the Start's
// pre-start always runs alone and one k0s runs at a time.
func TestStopThenStartNeverRunsTwoPreStarts(t *testing.T) {
	r := newPrepRunner()
	o := opts()
	o.Backoff = time.Nanosecond
	s := services.NewSupervisor(r, productTable(t), o)
	ctx := context.Background()
	go func() {
		for range r.entered {
		}
	}()
	if err := s.EnterPhase(ctx, phase.Normal); err != nil {
		t.Fatal(err)
	}
	for range 200 {
		if err := s.Stop("k0s"); err != nil {
			t.Fatal(err)
		}
		if err := s.Start(ctx, "k0s"); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	preps, maxPrep, starts, maxLive := r.counts()
	if maxPrep != 1 || maxLive != 1 || preps != starts || starts != 201 {
		t.Fatalf("preps %d (at once %d), starts %d (at once %d); want 201 of each, one at a time", preps, maxPrep, starts, maxLive)
	}
}
