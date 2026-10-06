// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package services_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/services"
)

// fakeRunner starts fake processes that run until signalled or told to
// exit, and records every start and run.
type fakeRunner struct {
	mu      sync.Mutex
	log     []string
	procs   map[string]*fakeProc
	files   map[string]bool
	failRun map[string]bool
}

type fakeProc struct {
	exit chan error
	once sync.Once
}

func (p *fakeProc) Wait() error { return <-p.exit }
func (p *fakeProc) Signal(os.Signal) error {
	p.once.Do(func() { p.exit <- nil })
	return nil
}
func (p *fakeProc) crash() { p.once.Do(func() { p.exit <- errors.New("exit status 1") }) }

func newRunner() *fakeRunner {
	return &fakeRunner{procs: map[string]*fakeProc{}, files: map[string]bool{}, failRun: map[string]bool{}}
}

func (r *fakeRunner) Start(argv []string) (services.Process, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log = append(r.log, "start "+argv[0])
	p := &fakeProc{exit: make(chan error, 1)}
	r.procs[argv[0]] = p
	return p, nil
}

func (r *fakeRunner) Run(_ context.Context, argv []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log = append(r.log, "run "+strings.Join(argv, " "))
	if r.failRun[argv[0]] {
		return errors.New("exit status 1")
	}
	return nil
}

func (r *fakeRunner) Exists(p string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.files[p]
}

func (r *fakeRunner) starts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, l := range r.log {
		if strings.HasPrefix(l, "start ") {
			out = append(out, strings.TrimPrefix(l, "start "))
		}
	}
	return out
}

func (r *fakeRunner) proc(exec string) *fakeProc {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.procs[exec]
}

func loadTable(t *testing.T) services.Table {
	t.Helper()
	tbl, err := services.Load(os.DirFS("testdata"), "services.d")
	if err != nil {
		t.Fatal(err)
	}
	return tbl
}

func opts() services.Options {
	return services.Options{Backoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond, ReadyTimeout: 2 * time.Second, StopTimeout: time.Second}
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSupervisorStartsOnlyPhaseServices(t *testing.T) {
	r := newRunner()
	s := services.NewSupervisor(r, loadTable(t), opts())
	if err := s.EnterPhase(context.Background(), phase.Firstboot); err != nil {
		t.Fatal(err)
	}
	if s.Running("k0s") || !s.Running("firstboot") || !s.Running("console") || s.Running("sshd") {
		t.Fatalf("wrong services for firstboot: %v", r.starts())
	}
	got := strings.Join(r.starts(), " ")
	if strings.Index(got, "console") > strings.Index(got, "firstboot") {
		t.Fatalf("firstboot started before console: %s", got)
	}
}

func TestEnteringNormalStopsFirstbootAndStartsK0sAfterPlatformd(t *testing.T) {
	r := newRunner()
	s := services.NewSupervisor(r, loadTable(t), opts())
	ctx := context.Background()
	_ = s.EnterPhase(ctx, phase.Firstboot)
	r.mu.Lock()
	r.files["/run/sneakers/platformd.ready"] = true
	r.mu.Unlock()
	if err := s.EnterPhase(ctx, phase.Normal); err != nil {
		t.Fatal(err)
	}
	if s.Running("firstboot") || !s.Running("k0s") || !s.Running("platformd") {
		t.Fatalf("normal: %v", r.starts())
	}
	r.mu.Lock()
	log := strings.Join(r.log, "\n")
	r.mu.Unlock()
	if !strings.Contains(log, "run /usr/libexec/sneakers/platformd prepare\nstart /usr/bin/k0s") {
		t.Fatalf("pre-start must run right before k0s:\n%s", log)
	}
}

func TestPreStartFailureKeepsTheServiceDown(t *testing.T) {
	r := newRunner()
	r.failRun["/usr/libexec/sneakers/platformd"] = true
	r.files["/run/sneakers/platformd.ready"] = true
	tbl := loadTable(t)
	tbl["k0s"].Restart = services.RestartNever
	s := services.NewSupervisor(r, tbl, opts())
	_ = s.EnterPhase(context.Background(), phase.Normal)
	if s.Running("k0s") {
		t.Fatal("k0s started although its pre-start failed")
	}
	st, _ := s.Status("k0s")
	if !strings.Contains(st.LastErr, "pre-start") {
		t.Fatalf("status %+v", st)
	}
}

func TestOnDemandOnlyStartsWhenAsked(t *testing.T) {
	r := newRunner()
	s := services.NewSupervisor(r, loadTable(t), opts())
	ctx := context.Background()
	_ = s.EnterPhase(ctx, phase.Firstboot)
	if s.Running("sshd") {
		t.Fatal("on-demand started by itself")
	}
	if err := s.Start(ctx, "sshd"); err != nil || !s.Running("sshd") {
		t.Fatalf("Start failed: %v", err)
	}
	if err := s.Stop("sshd"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "sshd to stop", func() bool { return !s.Running("sshd") })
	if err := s.Start(ctx, "console"); !codes.Is(err, codes.ServiceNotOnDemand) {
		t.Fatalf("got %v", err)
	}
	if err := s.Start(ctx, "nope"); !codes.Is(err, codes.ServiceUnknown) {
		t.Fatalf("got %v", err)
	}
}

func TestRestartPolicies(t *testing.T) {
	r := newRunner()
	s := services.NewSupervisor(r, loadTable(t), opts())
	_ = s.EnterPhase(context.Background(), phase.Firstboot)
	r.proc("/usr/libexec/sneakers/console").crash()
	eventually(t, "console to restart", func() bool {
		st, _ := s.Status("console")
		return st.Running && st.Restarts == 1
	})
	// firstboot is on-failure: a clean exit (its finish) isn't restarted.
	_ = r.proc("/usr/libexec/sneakers/firstboot").Signal(os.Interrupt)
	time.Sleep(50 * time.Millisecond)
	if s.Running("firstboot") {
		t.Fatal("a clean exit of an on-failure service must not restart")
	}
}

func TestReadinessGatesDependents(t *testing.T) {
	r := newRunner()
	tbl := loadTable(t)
	s := services.NewSupervisor(r, tbl, services.Options{Backoff: time.Millisecond, ReadyTimeout: 300 * time.Millisecond, StopTimeout: time.Second})
	done := make(chan struct{})
	go func() { _ = s.EnterPhase(context.Background(), phase.Normal); close(done) }()
	time.Sleep(100 * time.Millisecond)
	if s.Running("k0s") {
		t.Fatal("k0s started before platformd was ready")
	}
	r.mu.Lock()
	r.files["/run/sneakers/platformd.ready"] = true
	r.mu.Unlock()
	<-done
	if !s.Running("k0s") {
		t.Fatal("k0s didn't start once platformd was ready")
	}
}

func TestLoadRefusals(t *testing.T) {
	cases := map[string]fstest.MapFS{
		"relative exec": {"d/a.yaml": {Data: []byte("exec: bin/a\nphases: [normal]\n")}},
		"no phases":     {"d/a.yaml": {Data: []byte("exec: /a\n")}},
		"unknown phase": {"d/a.yaml": {Data: []byte("exec: /a\nphases: [later]\n")}},
		"unknown field": {"d/a.yaml": {Data: []byte("exec: /a\nphases: [normal]\nuser: root\n")}},
		"unknown after": {"d/a.yaml": {Data: []byte("exec: /a\nphases: [normal]\nafter: [b]\n")}},
		"bad restart":   {"d/a.yaml": {Data: []byte("exec: /a\nphases: [normal]\nrestart: sometimes\n")}},
		"after loop":    {"d/a.yaml": {Data: []byte("exec: /a\nphases: [normal]\nafter: [b]\n")}, "d/b.yaml": {Data: []byte("exec: /b\nphases: [normal]\nafter: [a]\n")}},
		"bad name":      {"d/A_b.yaml": {Data: []byte("exec: /a\nphases: [normal]\n")}},
		"two readiness": {"d/a.yaml": {Data: []byte("exec: /a\nphases: [normal]\nreadiness: {file: /x, exec: [/y]}\n")}},
	}
	for name, fsys := range cases {
		if _, err := services.Load(fsys, "d"); !codes.Is(err, codes.ServiceTableInvalid) {
			t.Errorf("%s: want SERVICE_TABLE_INVALID, got %v", name, err)
		}
	}
}

func TestExecRunnerWithRealProcesses(t *testing.T) {
	tbl := services.Table{"sleeper": {Name: "sleeper", Exec: "/bin/sleep", Args: []string{"30"}, Phases: []phase.Phase{phase.Normal}, Restart: services.RestartAlways, Start: services.StartAlways}}
	if _, err := os.Stat("/bin/sleep"); err != nil {
		t.Skip("no /bin/sleep")
	}
	s := services.NewSupervisor(services.ExecRunner{}, tbl, opts())
	_ = s.EnterPhase(context.Background(), phase.Normal)
	if !s.Running("sleeper") {
		t.Fatal("sleep isn't running")
	}
	_ = s.EnterPhase(context.Background(), phase.Firstboot)
	eventually(t, "sleep to stop", func() bool { return !s.Running("sleeper") })
}
