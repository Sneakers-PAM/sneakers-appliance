// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package services_test

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/services"
)

const (
	setupDone = "/var/lib/sneakers/setup/done"
	installed = "/var/lib/sneakers/product/current/bundle.json"
)

func gatedTable(t *testing.T) services.Table {
	t.Helper()
	tbl, err := services.Load(fstest.MapFS{
		"d/netd.yaml": {Data: []byte("exec: /usr/bin/netd\nphases: [normal]\nrestart: always\n")},
		"d/k0s.yaml":  {Data: []byte("exec: /usr/bin/k0s\nphases: [normal]\nafter: [netd]\nrestart: always\nstart-when: [" + setupDone + ", " + installed + "]\n")},
	}, "d")
	if err != nil {
		t.Fatal(err)
	}
	return tbl
}

func gatedOpts() services.Options {
	o := opts()
	o.WaitPoll = 5 * time.Millisecond
	return o
}

func TestAServiceWaitsWhileAStartWhenPathIsMissing(t *testing.T) {
	r := newRunner()
	r.files[setupDone] = true
	s := services.NewSupervisor(r, gatedTable(t), gatedOpts())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.EnterPhase(ctx, phase.Normal); err != nil {
		t.Fatal(err)
	}
	eventually(t, "netd", func() bool { return s.Running("netd") })
	time.Sleep(50 * time.Millisecond)
	if s.Running("k0s") {
		t.Fatal("k0s started with no product installed")
	}
	st, err := s.Status("k0s")
	if err != nil || !strings.Contains(st.LastErr, installed) || !strings.Contains(st.LastErr, "SERVICE_WAITING") {
		t.Fatalf("status %+v, %v", st, err)
	}
}

func TestAServiceStartsOnceItsPathsAppear(t *testing.T) {
	r := newRunner()
	s := services.NewSupervisor(r, gatedTable(t), gatedOpts())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.EnterPhase(ctx, phase.Normal); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.files[setupDone] = true
	r.mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	if s.Running("k0s") {
		t.Fatal("k0s started before the product was installed")
	}
	r.mu.Lock()
	r.files[installed] = true
	r.mu.Unlock()
	eventually(t, "k0s once the product is installed", func() bool { return s.Running("k0s") })
}

func TestAServiceWhosePathsExistStartsWithItsPhase(t *testing.T) {
	r := newRunner()
	r.files[setupDone], r.files[installed] = true, true
	s := services.NewSupervisor(r, gatedTable(t), gatedOpts())
	if err := s.EnterPhase(context.Background(), phase.Normal); err != nil {
		t.Fatal(err)
	}
	eventually(t, "k0s", func() bool { return s.Running("k0s") })
}

func TestServicesStartOverridesTheWaitAndStopHoldsIt(t *testing.T) {
	r := newRunner()
	s := services.NewSupervisor(r, gatedTable(t), gatedOpts())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.EnterPhase(ctx, phase.Normal); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx, "k0s"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "k0s started on request", func() bool { return s.Running("k0s") })
	if err := s.Stop("k0s"); err != nil {
		t.Fatal(err)
	}
	// Stopped on request, it stays stopped even once its paths exist,
	// until it's started again.
	r.mu.Lock()
	r.files[setupDone], r.files[installed] = true, true
	r.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	if s.Running("k0s") {
		t.Fatal("a stopped service came back on its own")
	}
	if err := s.Start(ctx, "k0s"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "k0s restarted", func() bool { return s.Running("k0s") })
}

func TestStartWhenTakesAbsolutePathsOnly(t *testing.T) {
	_, err := services.Load(fstest.MapFS{"d/x.yaml": {Data: []byte("exec: /bin/x\nphases: [normal]\nstart-when: [relative/path]\n")}}, "d")
	if !codes.Is(err, codes.ServiceTableInvalid) {
		t.Fatalf("want SERVICE_TABLE_INVALID, got %v", err)
	}
	_, err = services.Load(fstest.MapFS{"d/x.yaml": {Data: []byte("exec: /bin/x\nphases: [normal]\nstart: on-demand\nstart-when: [/a]\n")}}, "d")
	if !codes.Is(err, codes.ServiceTableInvalid) {
		t.Fatalf("on-demand with start-when: want SERVICE_TABLE_INVALID, got %v", err)
	}
}

func TestAServiceStartedThroughTheAPIKeepsItsRestartPolicy(t *testing.T) {
	r := newRunner()
	s := services.NewSupervisor(r, gatedTable(t), gatedOpts())
	phaseCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.EnterPhase(phaseCtx, phase.Normal); err != nil {
		t.Fatal(err)
	}
	// The request's context ends when the call returns; the restart policy
	// outlives it.
	reqCtx, end := context.WithCancel(context.Background())
	if err := s.Start(reqCtx, "k0s"); err != nil {
		t.Fatal(err)
	}
	end()
	eventually(t, "k0s", func() bool { return r.proc("/usr/bin/k0s") != nil })
	first := r.proc("/usr/bin/k0s")
	first.crash()
	eventually(t, "k0s restarted after a crash", func() bool { p := r.proc("/usr/bin/k0s"); return p != nil && p != first && s.Running("k0s") })
}
