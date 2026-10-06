// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
)

// Runner starts processes. The supervisor only speaks to it, so tests run
// the real sequencing against a fake.
type Runner interface {
	// Start starts argv and returns at once.
	Start(argv []string) (Process, error)
	// Run runs argv to completion (pre-start hooks, readiness probes).
	Run(ctx context.Context, argv []string) error
	// Exists reports whether a readiness file is present.
	Exists(path string) bool
}

// Process is one running program.
type Process interface {
	Wait() error
	Signal(sig os.Signal) error
}

// Options tune a supervisor.
type Options struct {
	Logger log.Logger
	// Backoff is the first restart delay, doubled up to MaxBackoff.
	Backoff, MaxBackoff time.Duration
	// ReadyTimeout bounds a readiness wait when the entry sets none.
	ReadyTimeout time.Duration
	// StopTimeout is how long a service gets after SIGTERM before SIGKILL.
	StopTimeout time.Duration
}

// State is what Status reports.
type State struct {
	Running  bool
	Ready    bool
	Restarts int
	LastErr  string
}

type unit struct {
	svc      *Service
	proc     Process
	wanted   bool
	ready    bool
	restarts int
	lastErr  string
	done     chan struct{}
}

// Supervisor runs the table's services for the current phase.
type Supervisor struct {
	r     Runner
	table Table
	o     Options

	mu    sync.Mutex
	phase phase.Phase
	units map[string]*unit
}

// NewSupervisor makes a supervisor for table.
func NewSupervisor(r Runner, table Table, o Options) *Supervisor {
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	if o.Backoff == 0 {
		o.Backoff = time.Second
	}
	if o.MaxBackoff == 0 {
		o.MaxBackoff = 30 * time.Second
	}
	if o.ReadyTimeout == 0 {
		o.ReadyTimeout = 2 * time.Minute
	}
	if o.StopTimeout == 0 {
		o.StopTimeout = 10 * time.Second
	}
	units := map[string]*unit{}
	for n, s := range table {
		units[n] = &unit{svc: s}
	}
	return &Supervisor{r: r, table: table, o: o, units: units}
}

// EnterPhase stops the services that don't run in p and starts, in after:
// order, the always-start services that do. A service that fails to start
// is logged and retried by its restart policy; it doesn't stop the others.
func (s *Supervisor) EnterPhase(ctx context.Context, p phase.Phase) error {
	s.mu.Lock()
	s.phase = p
	s.mu.Unlock()
	s.o.Logger.Info("services: entering phase", log.F("phase", string(p)))
	for _, n := range s.table.Names() {
		if !s.table[n].In(p) {
			s.stop(n)
		}
	}
	var start []string
	for _, n := range s.table.Names() {
		if sv := s.table[n]; sv.In(p) && sv.Start == StartAlways {
			start = append(start, n)
		}
	}
	order, err := s.table.order(start)
	if err != nil {
		return err
	}
	for _, n := range order {
		s.waitDeps(ctx, n)
		if err := s.start(ctx, n); err != nil {
			s.o.Logger.Error(err, "services: start failed", log.F("service", n))
		}
	}
	return nil
}

// Start starts an on-demand service of the current phase.
func (s *Supervisor) Start(ctx context.Context, name string) error {
	sv, err := s.onDemand(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	p := s.phase
	s.mu.Unlock()
	if !sv.In(p) {
		return codes.New(codes.ServiceNotOnDemand, "%s doesn't run in phase %s", name, p)
	}
	s.waitDeps(ctx, name)
	return s.start(ctx, name)
}

// Stop stops an on-demand service.
func (s *Supervisor) Stop(name string) error {
	if _, err := s.onDemand(name); err != nil {
		return err
	}
	s.stop(name)
	return nil
}

// Status reports one service.
func (s *Supervisor) Status(name string) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.units[name]
	if !ok {
		return State{}, codes.New(codes.ServiceUnknown, "no service %s", name)
	}
	return State{Running: u.proc != nil, Ready: u.ready, Restarts: u.restarts, LastErr: u.lastErr}, nil
}

// Running reports whether name has a live process.
func (s *Supervisor) Running(name string) bool {
	st, err := s.Status(name)
	return err == nil && st.Running
}

func (s *Supervisor) onDemand(name string) (*Service, error) {
	sv, ok := s.table[name]
	if !ok {
		return nil, codes.New(codes.ServiceUnknown, "no service %s", name)
	}
	if sv.Start != StartOnDemand {
		return nil, codes.New(codes.ServiceNotOnDemand, "%s starts with its phase, not on demand", name)
	}
	return sv, nil
}

// waitDeps waits until every after: service that's wanted is ready, or the
// readiness timeout passes (logged; the start goes ahead).
func (s *Supervisor) waitDeps(ctx context.Context, name string) {
	deadline := time.Now().Add(s.o.ReadyTimeout)
	for _, d := range s.table[name].After {
		for {
			s.mu.Lock()
			u := s.units[d]
			ok := !u.wanted || u.ready
			s.mu.Unlock()
			if ok {
				break
			}
			if time.Now().After(deadline) || ctx.Err() != nil {
				s.o.Logger.Warn("services: starting without a ready dependency", log.F("service", name), log.F("after", d))
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func (s *Supervisor) start(ctx context.Context, name string) error {
	s.mu.Lock()
	u := s.units[name]
	if u.proc != nil {
		s.mu.Unlock()
		return nil
	}
	u.wanted, u.ready = true, false
	s.mu.Unlock()
	return s.launch(ctx, u, s.o.Backoff)
}

func (s *Supervisor) launch(ctx context.Context, u *unit, backoff time.Duration) error {
	sv := u.svc
	if len(sv.PreStart) > 0 {
		if err := s.r.Run(ctx, sv.PreStart); err != nil {
			err = codes.New(codes.ServicePreStart, "%s: pre-start %s failed: %v", sv.Name, sv.PreStart[0], err)
			s.o.Logger.Error(err, "services: pre-start failed", log.F("service", sv.Name))
			s.exited(ctx, u, err, backoff)
			return err
		}
	}
	proc, err := s.r.Start(append([]string{sv.Exec}, sv.Args...))
	if err != nil {
		s.o.Logger.Error(err, "services: exec failed", log.F("service", sv.Name))
		s.exited(ctx, u, err, backoff)
		return err
	}
	done := make(chan struct{})
	s.mu.Lock()
	u.proc, u.done = proc, done
	s.mu.Unlock()
	s.o.Logger.Info("services: started", log.F("service", sv.Name))
	go func() {
		err := proc.Wait()
		close(done)
		s.mu.Lock()
		if u.proc == proc {
			u.proc = nil
			u.ready = false
		}
		s.mu.Unlock()
		s.exited(ctx, u, err, backoff)
	}()
	go s.probe(ctx, u, proc)
	return nil
}

func (s *Supervisor) probe(ctx context.Context, u *unit, proc Process) {
	r := u.svc.Readiness
	timeout := r.Timeout
	if timeout == 0 {
		timeout = s.o.ReadyTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		alive := u.proc == proc
		s.mu.Unlock()
		if !alive {
			return
		}
		ok := false
		switch {
		case r.File != "":
			ok = s.r.Exists(r.File)
		case len(r.Exec) > 0:
			ok = s.r.Run(ctx, r.Exec) == nil
		default:
			ok = true
		}
		if ok {
			s.mu.Lock()
			if u.proc == proc {
				u.ready = true
			}
			s.mu.Unlock()
			s.o.Logger.Info("services: ready", log.F("service", u.svc.Name))
			return
		}
		if time.Now().After(deadline) {
			s.o.Logger.Warn("services: not ready in time", log.F("service", u.svc.Name))
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// exited applies the restart policy after a process ends or fails to start.
func (s *Supervisor) exited(ctx context.Context, u *unit, err error, backoff time.Duration) {
	s.mu.Lock()
	if err != nil {
		u.lastErr = err.Error()
	}
	wanted := u.wanted && u.svc.In(s.phase)
	s.mu.Unlock()
	restart := wanted && (u.svc.Restart == RestartAlways || (u.svc.Restart == RestartOnFailure && err != nil))
	s.o.Logger.Info("services: exited", log.F("service", u.svc.Name), log.F("restart", restart), log.F("error", errString(err)))
	if !restart {
		return
	}
	go func() {
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		s.mu.Lock()
		again := u.wanted && u.proc == nil && u.svc.In(s.phase)
		if again {
			u.restarts++
		}
		s.mu.Unlock()
		if again {
			_ = s.launch(ctx, u, min(backoff*2, s.o.MaxBackoff))
		}
	}()
}

// stop ends a service: SIGTERM, then SIGKILL after StopTimeout.
func (s *Supervisor) stop(name string) {
	s.mu.Lock()
	u := s.units[name]
	u.wanted = false
	proc, done := u.proc, u.done
	s.mu.Unlock()
	if proc == nil {
		return
	}
	s.o.Logger.Info("services: stopping", log.F("service", name))
	_ = proc.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(s.o.StopTimeout):
		_ = proc.Signal(syscall.SIGKILL)
		<-done
	}
}

func errString(err error) string {
	if err == nil || errors.Is(err, context.Canceled) {
		return ""
	}
	return err.Error()
}
