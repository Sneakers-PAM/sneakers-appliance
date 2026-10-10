// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/accounts"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
)

// Runner starts processes. The supervisor only speaks to it, so tests run
// the real sequencing against a fake. A service with a user needs a Runner
// that is also a UserRunner.
type Runner interface {
	// Start starts argv and returns at once.
	Start(argv []string) (Process, error)
	// Run runs argv to completion (pre-start hooks, readiness probes).
	Run(ctx context.Context, argv []string) error
	// Exists reports whether a readiness file is present.
	Exists(path string) bool
}

// UserRunner starts a program under another uid and gid, keeping caps as
// ambient capabilities.
type UserRunner interface {
	StartAs(argv []string, uid, gid uint32, caps []uintptr) (Process, error)
}

// ConsoleRunner starts a program with its standard output on stdout (a
// claim on the consoles) and its standard error on the shared output.
type ConsoleRunner interface {
	StartConsole(argv []string, stdout *os.File) (Process, error)
}

// ConsoleOwner hands out claims on the consoles: the write end of a pipe
// whose output the consoles show while it's open.
type ConsoleOwner interface {
	Claim() (*os.File, error)
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
	// Console gives console services the consoles; nil starts them like
	// any other (the kernel's console is shared).
	Console ConsoleOwner
	// WaitPoll is how often a service waiting for its start-when paths
	// looks again; zero is five seconds.
	WaitPoll time.Duration
}

// State is what Status reports.
type State struct {
	Running  bool
	Ready    bool
	Restarts int
	LastErr  string
}

type unit struct {
	svc    *Service
	proc   Process
	wanted bool
	ready  bool
	// held is set by a Services.Stop: a gated service then stays stopped
	// until the next Start, whatever its paths.
	held     bool
	waiting  bool
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
	// ctx is the phase's context: what EnterPhase was given. Services
	// started through the API run under it, not under the request's.
	ctx   context.Context
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
	if o.WaitPoll == 0 {
		o.WaitPoll = 5 * time.Second
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
	s.phase, s.ctx = p, ctx
	s.mu.Unlock()
	s.o.Logger.Info("services: entering phase", log.F("phase", string(p)))
	for _, n := range s.table.Names() {
		if !s.table[n].In(p) {
			s.stop(n)
		}
	}
	var start []string
	for _, n := range s.table.Names() {
		sv := s.table[n]
		switch {
		case !sv.In(p) || sv.OnDemand(p):
		case sv.Gated(p) && s.missing(sv) != "":
			s.wait(ctx, p, n)
		default:
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

// missing is the first start-when path of sv that doesn't exist, or "".
func (s *Supervisor) missing(sv *Service) string {
	for _, p := range sv.StartWhen {
		if !s.r.Exists(p) {
			return p
		}
	}
	return ""
}

// wait marks name waiting for its start-when paths and starts it once they
// all exist, unless it's started or stopped through the API first or the
// phase changes.
func (s *Supervisor) wait(ctx context.Context, p phase.Phase, name string) {
	sv := s.table[name]
	s.mu.Lock()
	u := s.units[name]
	if u.waiting {
		s.mu.Unlock()
		return
	}
	u.waiting = true
	u.lastErr = codes.Describe(codes.New(codes.ServiceWaiting, "%s waits for %s", name, s.missing(sv)))
	s.mu.Unlock()
	s.o.Logger.Info("services: waiting for start-when paths", log.F("service", name), log.F("paths", strings.Join(sv.StartWhen, ",")))
	go func() {
		t := time.NewTicker(s.o.WaitPoll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			s.mu.Lock()
			stillWaiting := u.waiting && !u.held && !u.wanted && s.phase == p
			if !stillWaiting {
				u.waiting = false
				s.mu.Unlock()
				return
			}
			s.mu.Unlock()
			if m := s.missing(sv); m != "" {
				continue
			}
			s.mu.Lock()
			u.waiting, u.lastErr = false, ""
			s.mu.Unlock()
			s.o.Logger.Info("services: start-when paths present; starting", log.F("service", name))
			s.waitDeps(ctx, name)
			if err := s.start(ctx, name); err != nil {
				s.o.Logger.Error(err, "services: start failed", log.F("service", name))
			}
			return
		}
	}()
}

// Start starts an on-demand service of the current phase, or a gated one
// at once, whatever its start-when paths.
func (s *Supervisor) Start(ctx context.Context, name string) error {
	sv, err := s.onDemand(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	u := s.units[name]
	if u.waiting {
		u.lastErr = ""
	}
	u.held, u.waiting = false, false
	s.mu.Unlock()
	s.mu.Lock()
	p, run := s.phase, s.ctx
	s.mu.Unlock()
	if !sv.In(p) {
		return codes.New(codes.ServiceNotOnDemand, "%s doesn't run in phase %s", name, p)
	}
	if run == nil {
		run = ctx
	}
	s.waitDeps(ctx, name)
	return s.start(run, name)
}

// Stop stops an on-demand or a gated service; a gated one then stays
// stopped until the next Start.
func (s *Supervisor) Stop(name string) error {
	if _, err := s.onDemand(name); err != nil {
		return err
	}
	s.mu.Lock()
	u := s.units[name]
	u.held, u.waiting = true, false
	s.mu.Unlock()
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
	s.mu.Lock()
	p := s.phase
	s.mu.Unlock()
	if !sv.OnDemand(p) && !sv.Gated(p) {
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

// exec starts sv, as its user when it names one.
func (s *Supervisor) exec(sv *Service) (Process, error) {
	argv := append([]string{sv.Exec}, sv.Args...)
	if cr, ok := s.r.(ConsoleRunner); ok && sv.Console && s.o.Console != nil {
		w, err := s.o.Console.Claim()
		if err != nil {
			return nil, fmt.Errorf("%s: claim the console: %w", sv.Name, err)
		}
		// The program has its own copy; closing this one means the
		// console's claim ends when the program does.
		defer func() { _ = w.Close() }()
		s.o.Logger.Debug("services: starting with the console", log.F("service", sv.Name))
		return cr.StartConsole(argv, w)
	}
	if sv.User == "" {
		return s.r.Start(argv)
	}
	a, _ := accounts.ServiceUser(sv.User)
	ur, ok := s.r.(UserRunner)
	if !ok {
		return nil, fmt.Errorf("%s runs as %s, and this runner can't change user", sv.Name, sv.User)
	}
	s.o.Logger.Debug("services: starting as a system user", log.F("service", sv.Name), log.F("user", sv.User), log.F("uid", a.UID), log.F("capabilities", strings.Join(sv.Capabilities, ",")))
	return ur.StartAs(argv, uint32(a.UID), uint32(a.GID), sv.Caps()) // #nosec G115 -- fixed system ids below 65536
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
	proc, err := s.exec(sv)
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

// draining is the phase a drain leaves the supervisor in: no service runs
// in it, so nothing starts again until init reboots or powers off.
const draining phase.Phase = "draining"

// Drain stops every service but keep, dependents before what they run
// after (k0s before platformd), each with its own stop-timeout, and leaves
// the supervisor in a phase where nothing starts again. It's the graceful
// half of a reboot, a shutdown and a factory reset.
func (s *Supervisor) Drain(ctx context.Context, keep ...string) error {
	s.mu.Lock()
	s.phase = draining
	s.mu.Unlock()
	var names []string
	for _, n := range s.table.Names() {
		if !slices.Contains(keep, n) {
			names = append(names, n)
		}
	}
	order, err := s.table.order(names)
	if err != nil {
		return err
	}
	slices.Reverse(order)
	s.o.Logger.Info("services: draining", log.F("order", strings.Join(order, ",")), log.F("keep", strings.Join(keep, ",")))
	for _, n := range order {
		if err := ctx.Err(); err != nil {
			return err
		}
		start := time.Now()
		running := s.Running(n)
		s.stop(n)
		if running {
			s.o.Logger.Info("services: drained", log.F("service", n), log.F("took", time.Since(start).String()))
		}
	}
	return nil
}

// stop ends a service: its pre-stop, if it has one, then SIGTERM, then
// SIGKILL after its stop-timeout (the supervisor's StopTimeout when the
// entry sets none). The pre-stop gets the stop-timeout too.
func (s *Supervisor) stop(name string) {
	s.mu.Lock()
	u := s.units[name]
	u.wanted = false
	proc, done := u.proc, u.done
	s.mu.Unlock()
	if proc == nil {
		return
	}
	timeout := s.o.StopTimeout
	if t := s.table[name].StopTimeout; t > 0 {
		timeout = t
	}
	if pre := s.table[name].PreStop; len(pre) > 0 {
		s.preStop(name, pre, timeout)
	}
	s.o.Logger.Info("services: stopping", log.F("service", name))
	_ = proc.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(timeout):
		s.o.Logger.Warn("services: no exit after SIGTERM; killing", log.F("service", name), log.F("timeout", timeout.String()))
		_ = proc.Signal(syscall.SIGKILL)
		<-done
	}
}

// preStop runs a service's pre-stop within timeout; a failure is logged
// and never keeps the service from stopping.
func (s *Supervisor) preStop(name string, argv []string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	s.o.Logger.Info("services: pre-stop", log.F("service", name), log.F("exec", argv[0]), log.F("timeout", timeout.String()))
	if err := s.r.Run(ctx, argv); err != nil {
		s.o.Logger.Warn("services: pre-stop failed; stopping anyway", log.F("service", name), log.F("exec", argv[0]), log.F("took", time.Since(start).String()), log.F("error", err.Error()))
		return
	}
	s.o.Logger.Info("services: pre-stop done", log.F("service", name), log.F("took", time.Since(start).String()))
}

func errString(err error) string {
	if err == nil || errors.Is(err, context.Canceled) {
		return ""
	}
	return err.Error()
}
