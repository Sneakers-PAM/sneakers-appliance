// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package power_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/factoryreset"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/power"
)

var ctx = context.Background()

// box records, in order, what init did to the machine.
type box struct {
	mu       sync.Mutex
	steps    []string
	audit    []osaudit.Entry
	auditErr error
	drainErr error
}

func (b *box) add(s string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.steps = append(b.steps, s)
}

func (b *box) Drain(_ context.Context, keep ...string) error {
	b.add("drain keep=" + strings.Join(keep, ","))
	return b.drainErr
}
func (b *box) Sync()                              { b.add("sync") }
func (b *box) CloseVolumes(context.Context) error { b.add("close volumes"); return nil }
func (b *box) UnmountESP() error                  { b.add("unmount esp"); return nil }
func (b *box) Reboot() error                      { b.add("reboot"); return nil }
func (b *box) PowerOff() error                    { b.add("poweroff"); return nil }
func (b *box) Append(e osaudit.Entry) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.auditErr != nil {
		return b.auditErr
	}
	b.audit = append(b.audit, e)
	b.steps = append(b.steps, "audit "+e.Action+" "+e.Outcome)
	return nil
}

func (b *box) log() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.steps)
}

func (b *box) last() osaudit.Entry {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.audit[len(b.audit)-1]
}

// resetter stands in for the factory reset's own steps, tested in
// internal/factoryreset.
type resetter struct {
	b      *box
	began  []factoryreset.Record
	runErr error
}

func (r *resetter) Begin(rec factoryreset.Record) (factoryreset.Record, error) {
	r.began = append(r.began, rec)
	r.b.add("reset begin " + rec.ID)
	return rec, nil
}

func (r *resetter) Run(ctx context.Context, stop func(context.Context) error) (factoryreset.Record, error) {
	if err := stop(ctx); err != nil {
		return factoryreset.Record{}, err
	}
	r.b.add("reset run")
	return factoryreset.Record{Step: factoryreset.StepDone}, r.runErr
}

func roster() (access.State, error) {
	return access.State{Admins: []access.Admin{
		{Name: "alice", Role: access.RoleOwner, UID: 20000},
		{Name: "bob", Role: access.RoleOwner, UID: 20001},
		{Name: "carol", Role: access.RoleAdmin, UID: 20002},
	}}, nil
}

type fixture struct {
	b   *box
	r   *resetter
	clk *clock.Fake
	c   *power.Controller
}

func newController(t *testing.T) *fixture {
	t.Helper()
	b := &box{}
	f := &fixture{b: b, r: &resetter{b: b}, clk: clock.NewFake()}
	f.c = power.New(power.Options{
		Machine: b, Drainer: b, Audit: func() (power.Auditor, error) { return b, nil },
		Roster: roster, Reset: f.r, Clock: f.clk,
		Go: func(fn func()) { fn() },
	})
	return f
}

var (
	osadmin = power.Caller{Kind: power.KindOsadmin, UID: 0, PID: 300, Actor: "osadmin"}
	shell   = power.Caller{Kind: power.KindShell, UID: 20000, PID: 400, Actor: "alice"}
	forged  = power.Caller{Kind: power.KindUnknown, UID: 0, PID: 500, Actor: "/tmp/x"}
)

func TestGracefulRebootDrainsThenAuditsThenSyncsAndUnmounts(t *testing.T) {
	f := newController(t)
	if err := f.c.Reboot(ctx, shell, false); err != nil {
		t.Fatal(err)
	}
	want := []string{"audit power.reboot accepted", "drain keep=", "audit power.reboot ok", "sync", "close volumes", "unmount esp", "sync", "reboot"}
	if got := f.b.log(); !slices.Equal(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
	e := f.b.last()
	if e.Actor != "alice" || e.Detail["mode"] != "graceful" || e.Detail["caller"] != "shell" {
		t.Fatalf("%+v", e)
	}
}

func TestGracefulShutdownPowersOff(t *testing.T) {
	f := newController(t)
	if err := f.c.PowerOff(ctx, osadmin, false); err != nil {
		t.Fatal(err)
	}
	if got := f.b.log(); got[len(got)-1] != "poweroff" || !slices.Contains(got, "drain keep=") || f.b.last().Action != osaudit.ActionShutdown {
		t.Fatalf("%v", got)
	}
}

func TestForcedSkipsTheDrainButStillAuditsAndSyncs(t *testing.T) {
	for _, off := range []bool{false, true} {
		f := newController(t)
		var err error
		if off {
			err = f.c.PowerOff(ctx, osadmin, true)
		} else {
			err = f.c.Reboot(ctx, osadmin, true)
		}
		if err != nil {
			t.Fatal(err)
		}
		act, end := osaudit.ActionReboot, "reboot"
		if off {
			act, end = osaudit.ActionShutdown, "poweroff"
		}
		want := []string{"audit " + act + " accepted", "audit " + act + " ok", "sync", end}
		if got := f.b.log(); !slices.Equal(got, want) {
			t.Fatalf("got %v want %v", got, want)
		}
		if f.b.last().Detail["mode"] != "forced" {
			t.Fatalf("%+v", f.b.last())
		}
	}
}

func TestAFailedDrainStillRebootsAndIsAudited(t *testing.T) {
	f := newController(t)
	f.b.drainErr = errors.New("k0s didn't stop")
	if err := f.c.Reboot(ctx, osadmin, false); err != nil {
		t.Fatal(err)
	}
	got := f.b.log()
	if got[len(got)-1] != "reboot" || !slices.Contains(got, "audit power.reboot drain-failed") {
		t.Fatalf("%v", got)
	}
}

func TestAPowerRequestThatCantBeAuditedIsRefused(t *testing.T) {
	f := newController(t)
	f.b.auditErr = errors.New("the state volume is read-only")
	if err := f.c.Reboot(ctx, osadmin, false); err == nil {
		t.Fatal("an unaudited reboot went ahead")
	}
	if len(f.b.log()) != 0 {
		t.Fatalf("%v", f.b.log())
	}
}

func TestOnlyOsadminAndTheShellMayAskForPower(t *testing.T) {
	f := newController(t)
	err := f.c.Reboot(ctx, forged, false)
	if !codes.Is(err, codes.PowerCaller) {
		t.Fatalf("got %v", err)
	}
	if e := f.b.last(); e.Outcome != "refused" || e.Code != "POWER_CALLER" || e.Detail["pid"] != "500" {
		t.Fatalf("the refusal is audited: %+v", e)
	}
	if slices.Contains(f.b.log(), "reboot") {
		t.Fatal("a forged caller rebooted the box")
	}
}

func TestOnePowerActionAtATime(t *testing.T) {
	f := newController(t)
	var held func()
	c := power.New(power.Options{
		Machine: f.b, Drainer: f.b, Audit: func() (power.Auditor, error) { return f.b, nil },
		Roster: roster, Reset: f.r, Clock: f.clk,
		Go: func(fn func()) { held = fn },
	})
	if err := c.Reboot(ctx, osadmin, false); err != nil {
		t.Fatal(err)
	}
	if err := c.PowerOff(ctx, osadmin, true); !codes.Is(err, codes.PowerBusy) {
		t.Fatalf("got %v", err)
	}
	held()
}

func arm(t *testing.T, f *fixture, approvals ...string) {
	t.Helper()
	if _, err := f.c.Arm(osadmin, "R-ABC123", "alice", approvals); err != nil {
		t.Fatal(err)
	}
}

func TestTheFactoryResetRunsAfterInitsOwnDelay(t *testing.T) {
	f := newController(t)
	runsAt, err := f.c.Arm(osadmin, "R-ABC123", "alice", []string{"alice", "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if !runsAt.Equal(f.clk.Now().Add(power.ResetDelay)) {
		t.Fatalf("runs at %v", runsAt)
	}
	f.clk.Advance(power.ResetDelay - time.Second)
	err = f.c.FactoryReset(ctx, osadmin, "R-ABC123", "alice", []string{"alice", "bob"})
	if !codes.Is(err, codes.ResetQuorum) {
		t.Fatalf("before the delay: %v", err)
	}
	f.clk.Advance(time.Second)
	if err := f.c.FactoryReset(ctx, osadmin, "R-ABC123", "alice", []string{"bob", "alice"}); err != nil {
		t.Fatal(err)
	}
	want := []string{"reset begin R-ABC123", "drain keep=console", "close volumes", "reset run", "sync", "reboot"}
	got := f.b.log()
	var steps []string
	for _, s := range got {
		if !strings.HasPrefix(s, "audit ") {
			steps = append(steps, s)
		}
	}
	if !slices.Equal(steps, want) {
		t.Fatalf("got %v want %v", steps, want)
	}
	if !slices.Contains(got, "audit power.factory-reset.run accepted") || f.r.began[0].StartedBy != "alice" || len(f.r.began[0].Approvals) != 2 {
		t.Fatalf("%v %+v", got, f.r.began)
	}
}

func TestTheFactoryResetIsRefused(t *testing.T) {
	cases := []struct {
		name string
		do   func(f *fixture) error
		code int
	}{
		{"never armed", func(f *fixture) error {
			return f.c.FactoryReset(ctx, osadmin, "R-ABC123", "alice", []string{"alice", "bob"})
		}, codes.ResetQuorum},
		{"a bare flag: approvals that differ from the armed ones", func(f *fixture) error {
			arm(t, f, "alice", "bob")
			f.clk.Advance(power.ResetDelay)
			return f.c.FactoryReset(ctx, osadmin, "R-ABC123", "alice", []string{"alice", "carol"})
		}, codes.ResetQuorum},
		{"another request id", func(f *fixture) error {
			arm(t, f, "alice", "bob")
			f.clk.Advance(power.ResetDelay)
			return f.c.FactoryReset(ctx, osadmin, "R-OTHER1", "alice", []string{"alice", "bob"})
		}, codes.ResetQuorum},
		{"after a cancel", func(f *fixture) error {
			arm(t, f, "alice", "bob")
			if err := f.c.Cancel(osadmin, "R-ABC123", "bob"); err != nil {
				return err
			}
			f.clk.Advance(power.ResetDelay)
			return f.c.FactoryReset(ctx, osadmin, "R-ABC123", "alice", []string{"alice", "bob"})
		}, codes.ResetQuorum},
		{"expired", func(f *fixture) error {
			arm(t, f, "alice", "bob")
			f.clk.Advance(power.ResetDelay + power.ResetRunWindow + time.Second)
			return f.c.FactoryReset(ctx, osadmin, "R-ABC123", "alice", []string{"alice", "bob"})
		}, codes.ResetQuorum},
		{"from the shell", func(f *fixture) error {
			arm(t, f, "alice", "bob")
			f.clk.Advance(power.ResetDelay)
			return f.c.FactoryReset(ctx, shell, "R-ABC123", "alice", []string{"alice", "bob"})
		}, codes.PowerCaller},
		{"from a forged caller", func(f *fixture) error {
			arm(t, f, "alice", "bob")
			f.clk.Advance(power.ResetDelay)
			return f.c.FactoryReset(ctx, forged, "R-ABC123", "alice", []string{"alice", "bob"})
		}, codes.PowerCaller},
	}
	for _, c := range cases {
		f := newController(t)
		err := c.do(f)
		if !codes.Is(err, c.code) {
			t.Errorf("%s: got %v", c.name, err)
			continue
		}
		if len(f.r.began) != 0 || slices.Contains(f.b.log(), "reboot") {
			t.Errorf("%s: the reset began", c.name)
		}
		if e := f.b.last(); e.Outcome != "refused" {
			t.Errorf("%s: the refusal isn't audited: %+v", c.name, e)
		}
	}
}

func TestArmingChecksTheRosterItself(t *testing.T) {
	cases := []struct {
		name      string
		caller    power.Caller
		startedBy string
		approvals []string
		code      int
	}{
		{"one approval", osadmin, "alice", []string{"alice"}, codes.ResetQuorum},
		{"the same admin twice", osadmin, "alice", []string{"alice", "alice"}, codes.ResetQuorum},
		{"someone who isn't an admin", osadmin, "alice", []string{"alice", "mallory"}, codes.ResetQuorum},
		{"started by an admin who isn't an owner", osadmin, "carol", []string{"alice", "bob"}, codes.ResetQuorum},
		{"armed by the shell", shell, "alice", []string{"alice", "bob"}, codes.PowerCaller},
	}
	for _, c := range cases {
		f := newController(t)
		if _, err := f.c.Arm(c.caller, "R-ABC123", c.startedBy, c.approvals); !codes.Is(err, c.code) {
			t.Errorf("%s: got %v", c.name, err)
		}
	}
}

func TestARosterChangeDuringTheDelayIsCheckedAgain(t *testing.T) {
	st, _ := roster()
	cur := st
	f := newController(t)
	f.c = power.New(power.Options{
		Machine: f.b, Drainer: f.b, Audit: func() (power.Auditor, error) { return f.b, nil },
		Roster: func() (access.State, error) { return cur, nil }, Reset: f.r, Clock: f.clk,
		Go: func(fn func()) { fn() },
	})
	arm(t, f, "alice", "bob")
	cur.Quorum = &access.QuorumRoster{Members: []string{"alice", "carol"}, Required: 2}
	f.clk.Advance(power.ResetDelay)
	if err := f.c.FactoryReset(ctx, osadmin, "R-ABC123", "alice", []string{"alice", "bob"}); !codes.Is(err, codes.ResetQuorum) {
		t.Fatalf("got %v", err)
	}
}

func TestAResetThatFailsLiveRebootsToFinishAtBoot(t *testing.T) {
	f := newController(t)
	f.r.runErr = codes.New(codes.ResetFailed, "the state volume is busy")
	arm(t, f, "alice", "bob")
	f.clk.Advance(power.ResetDelay)
	if err := f.c.FactoryReset(ctx, osadmin, "R-ABC123", "alice", []string{"alice", "bob"}); err != nil {
		t.Fatal(err)
	}
	if got := f.b.log(); got[len(got)-1] != "reboot" {
		t.Fatalf("%v", got)
	}
}

func TestAResetWhoseCheckFailsDoesntReboot(t *testing.T) {
	f := newController(t)
	f.r.runErr = codes.New(codes.ResetVerify, "sneakers-state is still in the GPT")
	arm(t, f, "alice", "bob")
	f.clk.Advance(power.ResetDelay)
	if err := f.c.FactoryReset(ctx, osadmin, "R-ABC123", "alice", []string{"alice", "bob"}); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.b.log(), "reboot") {
		t.Fatal("a reset whose check failed rebooted")
	}
}

// The screen says what's happening before anything stops: Announce runs
// with the action before the drain, graceful or forced.
func TestTheActionIsAnnouncedBeforeTheDrain(t *testing.T) {
	for _, tc := range []struct {
		off, forced bool
		want        string
	}{{false, false, osaudit.ActionReboot}, {true, false, osaudit.ActionShutdown}, {false, true, osaudit.ActionReboot}, {true, true, osaudit.ActionShutdown}} {
		b := &box{}
		c := power.New(power.Options{
			Machine: b, Drainer: b, Audit: func() (power.Auditor, error) { return b, nil },
			Roster: roster, Reset: &resetter{b: b}, Clock: clock.NewFake(),
			Go:       func(fn func()) { fn() },
			Announce: func(action string) { b.add("announce " + action) },
		})
		var err error
		if tc.off {
			err = c.PowerOff(ctx, osadmin, tc.forced)
		} else {
			err = c.Reboot(ctx, osadmin, tc.forced)
		}
		if err != nil {
			t.Fatal(err)
		}
		got := b.log()
		if len(got) < 2 || got[1] != "announce "+tc.want {
			t.Fatalf("off=%v forced=%v: %v", tc.off, tc.forced, got)
		}
	}
}

// A reboot or a shutdown leaves Keep running through the drain (the edge
// fallback, which answers 443 until the power goes).
func TestTheDrainKeepsWhatItIsToldTo(t *testing.T) {
	for _, act := range []func(*power.Controller) error{
		func(c *power.Controller) error { return c.Reboot(ctx, osadmin, false) },
		func(c *power.Controller) error { return c.PowerOff(ctx, osadmin, false) },
	} {
		b := &box{}
		c := power.New(power.Options{
			Machine: b, Drainer: b, Audit: func() (power.Auditor, error) { return b, nil },
			Roster: roster, Reset: &resetter{b: b}, Clock: clock.NewFake(),
			Go:   func(fn func()) { fn() },
			Keep: []string{"edgefall"},
		})
		if err := act(c); err != nil {
			t.Fatal(err)
		}
		if got := b.log(); !slices.Contains(got, "drain keep=edgefall") {
			t.Fatalf("%v", got)
		}
	}
}
