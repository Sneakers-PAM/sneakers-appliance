// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package services_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/services"
)

// stopRunner records the order processes are signalled in; a process
// named in slow ignores SIGTERM until it is killed.
type stopRunner struct {
	*fakeRunner
	mu      sync.Mutex
	stopped []string
	slow    map[string]bool
}

type namedProc struct {
	*fakeProc
	name string
	r    *stopRunner
}

func (p namedProc) Signal(sig os.Signal) error {
	p.r.mu.Lock()
	p.r.stopped = append(p.r.stopped, p.name+" "+sig.String())
	slow := p.r.slow[p.name]
	p.r.mu.Unlock()
	if slow && sig.String() != "killed" {
		return nil
	}
	return p.fakeProc.Signal(sig)
}

func (r *stopRunner) Start(argv []string) (services.Process, error) {
	p, err := r.fakeRunner.Start(argv)
	if err != nil {
		return nil, err
	}
	return namedProc{fakeProc: p.(*fakeProc), name: argv[0], r: r}, nil
}

func (r *stopRunner) order() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.stopped...)
}

func TestDrainStopsDependentsFirstAndKeepsTheNamedOnes(t *testing.T) {
	r := &stopRunner{fakeRunner: newRunner(), slow: map[string]bool{}}
	r.files["/run/sneakers/platformd.ready"] = true
	s := services.NewSupervisor(r, loadTable(t), opts())
	if err := s.EnterPhase(context.Background(), phase.Normal); err != nil {
		t.Fatal(err)
	}
	eventually(t, "k0s", func() bool { return s.Running("k0s") })
	if err := s.Drain(context.Background(), "console"); err != nil {
		t.Fatal(err)
	}
	got := r.order()
	want := []string{"/usr/bin/k0s terminated", "/usr/libexec/sneakers/platformd terminated"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("stop order %v, want %v", got, want)
	}
	if !s.Running("console") || s.Running("k0s") || s.Running("platformd") {
		t.Fatal("drain kept the wrong services")
	}
	if err := s.Start(context.Background(), "sshd"); !codes.Is(err, codes.ServiceNotOnDemand) {
		t.Fatalf("an on-demand start after the drain: %v", err)
	}
}

func TestDrainGivesEachServiceItsStopTimeout(t *testing.T) {
	r := &stopRunner{fakeRunner: newRunner(), slow: map[string]bool{"/usr/bin/k0s": true}}
	r.files["/run/sneakers/platformd.ready"] = true
	tbl := loadTable(t)
	if tbl["k0s"].StopTimeout != 2*time.Minute {
		t.Fatalf("k0s stop-timeout %v", tbl["k0s"].StopTimeout)
	}
	tbl["k0s"].StopTimeout = 50 * time.Millisecond
	o := opts()
	o.StopTimeout = time.Hour
	s := services.NewSupervisor(r, tbl, o)
	if err := s.EnterPhase(context.Background(), phase.Normal); err != nil {
		t.Fatal(err)
	}
	eventually(t, "k0s", func() bool { return s.Running("k0s") })
	start := time.Now()
	if err := s.Drain(context.Background(), "console", "platformd"); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 10*time.Second || s.Running("k0s") {
		t.Fatal("k0s wasn't killed after its own stop-timeout")
	}
	if got := r.order(); len(got) != 2 || got[1] != "/usr/bin/k0s killed" {
		t.Fatalf("signals %v", got)
	}
}
