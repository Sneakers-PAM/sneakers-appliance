// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package power is init's side of reboot, shutdown and the factory reset
// (spec 2, Section 2.12; spec 5, Section 2.8.1). osadmin and the closed
// shell decide whether someone may ask; init checks who is asking, audits
// every request and its outcome, and does the work: a graceful drain or a
// forced stop, then sync, unmount and the reboot or power-off. A factory
// reset runs only once osadmin has armed it with a quorum init checks
// against the access store itself, init's own delay has passed, and nobody
// cancelled it.
package power

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/factoryreset"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// The factory reset's timings, counted by init on its monotonic clock.
const (
	// ResetDelay runs from the arming to the earliest run: osadmin's
	// 10-minute Cancel window.
	ResetDelay = 10 * time.Minute
	// ResetRunWindow is how long after the delay an armed reset may still
	// run; later it has expired and is forgotten.
	ResetRunWindow = 5 * time.Minute
)

// The audit actions init writes beside osadmin's power.reboot and
// power.shutdown.
const (
	ActionResetArm    = "power.factory-reset.arm"
	ActionResetCancel = "power.factory-reset.cancel"
	ActionResetRun    = "power.factory-reset.run"
)

// Kind is which program is on the other end of the socket.
type Kind string

// The callers init answers, and everything else.
const (
	KindOsadmin Kind = "osadmin"
	KindShell   Kind = "shell"
	KindUnknown Kind = "unknown"
)

// Caller is who asked: the peer's credentials and the program it runs.
type Caller struct {
	Kind Kind
	UID  uint32
	PID  int32
	// Actor is the name the audit entry records: the admin a shell login
	// belongs to, console for the console's shell, osadmin, or the
	// unknown program's path.
	Actor string
}

// Machine is the hardware end.
type Machine interface {
	Sync()
	// CloseVolumes unmounts the state and backup volumes and closes their
	// LUKS mappings.
	CloseVolumes(ctx context.Context) error
	UnmountESP() error
	Reboot() error
	PowerOff() error
}

// Drainer is the service supervisor.
type Drainer interface {
	Drain(ctx context.Context, keep ...string) error
}

// Auditor is the OS audit log.
type Auditor interface {
	Append(osaudit.Entry) error
}

// Resetter is the factory reset itself.
type Resetter interface {
	Begin(factoryreset.Record) (factoryreset.Record, error)
	// Run carries the reset out; stop drains and closes the volumes.
	Run(ctx context.Context, stop func(context.Context) error) (factoryreset.Record, error)
}

// Options are the controller's collaborators.
type Options struct {
	Machine Machine
	Drainer Drainer
	// Audit opens the OS audit log; it's on the state volume, so it's
	// opened when first needed.
	Audit func() (Auditor, error)
	// Roster reads the access store.
	Roster func() (access.State, error)
	Reset  Resetter
	Clock  clock.Clock
	Logger log.Logger
	// Go runs the work after the request is answered; nil means a
	// goroutine.
	Go func(func())
	// DrainTimeout bounds a graceful drain; zero means 5 minutes.
	DrainTimeout time.Duration
	// Announce, when set, is told a reboot or a shutdown is under way
	// (power.reboot or power.shutdown) before anything stops: init puts
	// the rebooting or shutting down screen up.
	Announce func(action string)
}

// armed is the reset osadmin armed.
type armed struct {
	id        string
	startedBy string
	approvals []string
	at        time.Duration // monotonic
	runsAt    time.Time
}

// Controller is init's PowerService.
type Controller struct {
	o     Options
	mu    sync.Mutex
	busy  bool
	armed *armed
}

// New makes a controller.
func New(o Options) *Controller {
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	if o.Go == nil {
		o.Go = func(f func()) { go f() }
	}
	if o.DrainTimeout == 0 {
		o.DrainTimeout = 5 * time.Minute
	}
	return &Controller{o: o}
}

func entry(c Caller, action, target string) osaudit.Entry {
	return osaudit.Entry{Actor: c.Actor, Action: action, Target: target, Detail: map[string]string{
		"surface": "init", "caller": string(c.Kind), "uid": strconv.FormatUint(uint64(c.UID), 10), "pid": strconv.Itoa(int(c.PID)),
	}}
}

// audit appends e with outcome and the error's code.
func (c *Controller) audit(e osaudit.Entry, outcome string, err error) error {
	e.Outcome = outcome
	if err != nil {
		if code, ok := codes.Of(err); ok {
			e.Code = symbol(code)
		}
		e.Detail["error"] = codes.Describe(err)
	}
	a, aerr := c.o.Audit()
	if aerr == nil {
		aerr = a.Append(e)
	}
	if aerr != nil {
		c.o.Logger.Error(aerr, "power: audit append failed", log.F("action", e.Action), log.F("outcome", outcome))
		return codes.New(codes.PowerAudit, "the OS audit log can't be written, so init won't act: %v", aerr)
	}
	return nil
}

func symbol(code int) string {
	for _, e := range codes.Entries {
		if e.Code == code {
			return e.Symbol
		}
	}
	return strconv.Itoa(code)
}

// refuse audits a refusal and returns err.
func (c *Controller) refuse(e osaudit.Entry, err error) error {
	_ = c.audit(e, "refused", err)
	c.o.Logger.Warn("power: refused", log.F("action", e.Action), log.F("actor", e.Actor), log.F("error", codes.Describe(err)))
	return err
}

func powerCaller(c Caller, resetOnly bool) error {
	switch {
	case c.Kind == KindOsadmin:
		return nil
	case c.Kind == KindShell && !resetOnly:
		return nil
	case c.Kind == KindShell:
		return codes.New(codes.PowerCaller, "a factory reset can't come from the closed shell; start it on :8443")
	default:
		return codes.New(codes.PowerCaller, "%s isn't osadmin or the closed shell", c.Actor)
	}
}

// Reboot reboots the box: drained unless forced.
func (c *Controller) Reboot(ctx context.Context, caller Caller, forced bool) error {
	return c.stop(ctx, caller, osaudit.ActionReboot, forced)
}

// PowerOff shuts the box down: drained unless forced.
func (c *Controller) PowerOff(ctx context.Context, caller Caller, forced bool) error {
	return c.stop(ctx, caller, osaudit.ActionShutdown, forced)
}

func (c *Controller) stop(_ context.Context, caller Caller, action string, forced bool) error {
	e := entry(caller, action, "box")
	mode := "graceful"
	if forced {
		mode = "forced"
	}
	e.Detail["mode"] = mode
	if err := powerCaller(caller, false); err != nil {
		return c.refuse(e, err)
	}
	if err := c.claim(); err != nil {
		return c.refuse(e, err)
	}
	if err := c.audit(e, "accepted", nil); err != nil {
		c.release()
		return err
	}
	c.o.Logger.Info("power: accepted", log.F("action", action), log.F("actor", caller.Actor), log.F("mode", mode))
	c.o.Go(func() { c.finish(e, action, forced) })
	return nil
}

// finish runs after the request is answered.
func (c *Controller) finish(e osaudit.Entry, action string, forced bool) {
	if c.o.Announce != nil {
		c.o.Announce(action)
	}
	outcome := "ok"
	if !forced {
		start := c.o.Clock.Mono()
		dctx, cancel := context.WithTimeout(context.Background(), c.o.DrainTimeout)
		err := c.o.Drainer.Drain(dctx)
		cancel()
		if err != nil {
			// The box still goes down: a reboot that waits forever on a
			// stuck service is worse than one that kills it.
			outcome = "drain-failed"
			e.Detail["error"] = err.Error()
			c.o.Logger.Error(err, "power: the drain failed; going ahead", log.F("action", action))
		}
		e.Detail["drained"] = (c.o.Clock.Mono() - start).String()
	}
	_ = c.audit(e, outcome, nil)
	c.o.Machine.Sync()
	if !forced {
		if err := c.o.Machine.CloseVolumes(context.Background()); err != nil {
			c.o.Logger.Error(err, "power: close the volumes")
		}
		if err := c.o.Machine.UnmountESP(); err != nil {
			c.o.Logger.Error(err, "power: unmount the ESP")
		}
		c.o.Machine.Sync()
	}
	c.act(action)
}

func (c *Controller) act(action string) {
	var err error
	if action == osaudit.ActionShutdown {
		c.o.Logger.Info("power: powering off")
		err = c.o.Machine.PowerOff()
	} else {
		c.o.Logger.Info("power: rebooting")
		err = c.o.Machine.Reboot()
	}
	if err != nil {
		c.o.Logger.Error(err, "power: the "+action+" call failed")
		c.release()
	}
}

func (c *Controller) claim() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.busy {
		return codes.New(codes.PowerBusy, "a reboot, shutdown or factory reset is already under way")
	}
	c.busy = true
	return nil
}

func (c *Controller) release() {
	c.mu.Lock()
	c.busy = false
	c.mu.Unlock()
}

// checkQuorum checks approvals against the access store now: distinct
// members of the roster in force, at least its threshold, and a starter
// who is an owner.
func (c *Controller) checkQuorum(startedBy string, approvals []string) error {
	st, err := c.o.Roster()
	if err != nil {
		return codes.New(codes.ResetQuorum, "the access store can't be read: %v", err)
	}
	if a, ok := st.Admin(startedBy); !ok || a.Role != access.RoleOwner {
		return codes.New(codes.ResetQuorum, "%q isn't an owner", startedBy)
	}
	q := st.EffectiveQuorum()
	if !q.Available() {
		return codes.New(codes.ResetQuorum, "the roster has no quorum (%d members, %d required)", len(q.Members), q.Required)
	}
	seen := map[string]bool{}
	for _, a := range approvals {
		if seen[a] {
			return codes.New(codes.ResetQuorum, "%s is counted twice", a)
		}
		if !slices.Contains(q.Members, a) {
			return codes.New(codes.ResetQuorum, "%q isn't on the quorum roster", a)
		}
		seen[a] = true
	}
	if len(seen) < q.Required {
		return codes.New(codes.ResetQuorum, "%d approvals; the roster needs %d", len(seen), q.Required)
	}
	return nil
}

// Arm records a reset osadmin's quorum approved and starts init's delay.
func (c *Controller) Arm(caller Caller, id, startedBy string, approvals []string) (time.Time, error) {
	e := entry(caller, ActionResetArm, id)
	e.Detail["startedBy"], e.Detail["approvals"] = startedBy, fmt.Sprint(approvals)
	if err := powerCaller(caller, true); err != nil {
		return time.Time{}, c.refuse(e, err)
	}
	if err := c.checkQuorum(startedBy, approvals); err != nil {
		return time.Time{}, c.refuse(e, err)
	}
	c.mu.Lock()
	if c.busy || (c.armed != nil && c.armed.id != id) {
		c.mu.Unlock()
		return time.Time{}, c.refuse(e, codes.New(codes.ResetUnavailable, "a factory reset or another power action is already under way"))
	}
	a := &armed{id: id, startedBy: startedBy, approvals: slices.Clone(approvals), at: c.o.Clock.Mono(), runsAt: c.o.Clock.Now().Add(ResetDelay)}
	c.armed = a
	c.mu.Unlock()
	if err := c.audit(e, "ok", nil); err != nil {
		c.forget(id)
		return time.Time{}, err
	}
	c.o.Logger.Warn("power: factory reset armed", log.F("id", id), log.F("startedBy", startedBy), log.F("runsAt", a.runsAt))
	return a.runsAt, nil
}

func (c *Controller) forget(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.armed == nil || (id != "" && c.armed.id != id) {
		return false
	}
	c.armed = nil
	return true
}

// Cancel forgets an armed reset; an empty id cancels whichever is armed.
func (c *Controller) Cancel(caller Caller, id, actor string) error {
	e := entry(caller, ActionResetCancel, id)
	e.Detail["by"] = actor
	if err := powerCaller(caller, true); err != nil {
		return c.refuse(e, err)
	}
	if !c.forget(id) {
		return c.refuse(e, codes.New(codes.ResetCancelled, "no factory reset %q is armed", id))
	}
	c.o.Logger.Warn("power: factory reset cancelled", log.F("id", id), log.F("by", actor))
	return c.audit(e, "ok", nil)
}

// FactoryReset runs the armed reset id once the delay has passed. The
// request must name the armed request, its starter and its approvals, and
// the approvals must still be a quorum of the roster.
func (c *Controller) FactoryReset(_ context.Context, caller Caller, id, startedBy string, approvals []string) error {
	e := entry(caller, ActionResetRun, id)
	e.Detail["startedBy"], e.Detail["approvals"] = startedBy, fmt.Sprint(approvals)
	if err := powerCaller(caller, true); err != nil {
		return c.refuse(e, err)
	}
	c.mu.Lock()
	a := c.armed
	var err error
	switch {
	case a == nil || a.id != id:
		err = codes.New(codes.ResetQuorum, "init has no armed factory reset %q", id)
	case a.startedBy != startedBy || !sameSet(a.approvals, approvals):
		err = codes.New(codes.ResetQuorum, "the request doesn't match what was armed")
	case c.o.Clock.Mono()-a.at < ResetDelay:
		err = codes.New(codes.ResetQuorum, "the delay isn't over; the reset runs at %s", a.runsAt.Format(time.RFC3339))
	case c.o.Clock.Mono()-a.at > ResetDelay+ResetRunWindow:
		c.armed = nil
		err = codes.New(codes.ResetQuorum, "the armed reset expired")
	case c.busy:
		err = codes.New(codes.PowerBusy, "another power action is under way")
	}
	if err != nil {
		c.mu.Unlock()
		return c.refuse(e, err)
	}
	c.mu.Unlock()
	if err := c.checkQuorum(startedBy, approvals); err != nil {
		return c.refuse(e, err)
	}
	if err := c.claim(); err != nil {
		return c.refuse(e, err)
	}
	c.forget(id)
	if err := c.audit(e, "accepted", nil); err != nil {
		c.release()
		return err
	}
	rec, err := c.o.Reset.Begin(factoryreset.Record{ID: id, StartedBy: startedBy, Approvals: slices.Clone(approvals)})
	if err != nil {
		c.release()
		return c.refuse(e, err)
	}
	c.o.Logger.Warn("power: factory reset begun", log.F("id", id), log.F("partitions", len(rec.Regions)))
	c.o.Go(func() { c.runReset(id) })
	return nil
}

func (c *Controller) runReset(id string) {
	stop := func(ctx context.Context) error {
		dctx, cancel := context.WithTimeout(ctx, c.o.DrainTimeout)
		defer cancel()
		if err := c.o.Drainer.Drain(dctx, "console"); err != nil {
			c.o.Logger.Error(err, "power: the drain before the reset failed; closing the volumes anyway")
		}
		return c.o.Machine.CloseVolumes(ctx)
	}
	_, err := c.o.Reset.Run(context.Background(), stop)
	c.o.Machine.Sync()
	if codes.Is(err, codes.ResetVerify) {
		// Spec 5: a failed check stops here and shows itself; the box isn't
		// rebooted half-reset.
		c.o.Logger.Error(err, "power: the factory reset's check failed; not rebooting", log.F("id", id))
		return
	}
	if err != nil {
		// The record is pending, so the next boot finishes the reset with
		// nothing started or mounted.
		c.o.Logger.Error(err, "power: the factory reset failed; rebooting to finish it", log.F("id", id))
	}
	c.act(osaudit.ActionReboot)
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}
