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

// stopWatch is a runner whose pre-stop records whether the service still
// ran when it was called, and may take long or fail.
type stopWatch struct {
	*fakeRunner
	stillRunning bool
	hold         time.Duration
	fail         bool
	s            *services.Supervisor
}

func (r *stopWatch) Run(ctx context.Context, argv []string) error {
	if argv[0] == "/usr/bin/quiesce" {
		r.stillRunning = r.s.Running("k0s")
		select {
		case <-time.After(r.hold):
		case <-ctx.Done():
			return ctx.Err()
		}
		if r.fail {
			r.fakeRunner.mu.Lock()
			r.fakeRunner.log = append(r.fakeRunner.log, "run "+strings.Join(argv, " ")+" (failed)")
			r.fakeRunner.mu.Unlock()
			return context.DeadlineExceeded
		}
	}
	return r.fakeRunner.Run(ctx, argv)
}

func preStopTable(t *testing.T) services.Table {
	t.Helper()
	tbl := loadTable(t)
	tbl["k0s"].PreStop = []string{"/usr/bin/quiesce", "now"}
	tbl["k0s"].StopTimeout = 300 * time.Millisecond
	// As on the box, k0s waits for its paths, so Services.Stop may hold it.
	tbl["k0s"].StartWhen = []string{"/var/lib/sneakers/product/current/bundle.json"}
	return tbl
}

func normal(t *testing.T, r *stopWatch, tbl services.Table) *services.Supervisor {
	t.Helper()
	r.files["/run/sneakers/platformd.ready"] = true
	r.files["/var/lib/sneakers/product/current/bundle.json"] = true
	s := services.NewSupervisor(r, tbl, opts())
	r.s = s
	if err := s.EnterPhase(context.Background(), phase.Normal); err != nil {
		t.Fatal(err)
	}
	if !s.Running("k0s") {
		t.Fatal("k0s isn't running")
	}
	return s
}

// A service's pre-stop runs to completion while the service still runs,
// before its SIGTERM: on Stop and on a drain alike.
func TestPreStopRunsBeforeTheSignal(t *testing.T) {
	for name, stop := range map[string]func(*services.Supervisor) error{
		"Stop":  func(s *services.Supervisor) error { return s.Stop("k0s") },
		"Drain": func(s *services.Supervisor) error { return s.Drain(context.Background()) },
	} {
		t.Run(name, func(t *testing.T) {
			r := &stopWatch{fakeRunner: newRunner()}
			s := normal(t, r, preStopTable(t))
			if err := stop(s); err != nil {
				t.Fatal(err)
			}
			if !r.stillRunning {
				t.Fatal("the pre-stop ran after k0s stopped")
			}
			if s.Running("k0s") {
				t.Fatal("k0s still runs")
			}
			r.mu.Lock()
			defer r.mu.Unlock()
			if !strings.Contains(strings.Join(r.log, "\n"), "run /usr/bin/quiesce now") {
				t.Fatalf("no pre-stop:\n%s", strings.Join(r.log, "\n"))
			}
		})
	}
}

// A pre-stop that fails or outlasts the stop-timeout never keeps the
// service from stopping.
func TestAPreStopThatFailsOrHangsStillStops(t *testing.T) {
	for name, r := range map[string]*stopWatch{
		"fails": {fakeRunner: newRunner(), fail: true},
		"hangs": {fakeRunner: newRunner(), hold: time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			s := normal(t, r, preStopTable(t))
			done := make(chan error, 1)
			go func() { done <- s.Stop("k0s") }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Stop waited past the pre-stop's bound")
			}
			if s.Running("k0s") {
				t.Fatal("k0s still runs")
			}
		})
	}
}

// A pre-stop takes an absolute path, like a pre-start.
func TestAPreStopNeedsAnAbsolutePath(t *testing.T) {
	fsys := fstest.MapFS{"services.d/a.yaml": {Data: []byte("exec: /bin/a\nphases: [normal]\npre-stop: [quiesce]\n")}}
	if _, err := services.Load(fsys, "services.d"); !codes.Is(err, codes.ServiceTableInvalid) {
		t.Fatalf("a relative pre-stop: %v", err)
	}
}
