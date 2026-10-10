// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

// phasedProbe is a phased product: its steps, and the answer the test
// sets.
type phasedProbe struct {
	mu  sync.Mutex
	res productup.Result
}

func (f *phasedProbe) Check(context.Context) (productup.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.res, nil
}

func (f *phasedProbe) Steps() []productup.Step {
	return []productup.Step{
		{ID: productup.StepK0s, Label: "Starting k0s"}, {ID: productup.StepImages, Label: "Importing the images"},
		{ID: productup.StepQuiesce, Label: "Stopping what was left running"}, {ID: productup.StepCluster, Label: "Starting the cluster"},
		{ID: "phase:data", Label: "Starting the database"}, {ID: "phase:front", Label: "Starting the web apps"},
		{ID: productup.StepHealth, Label: "Checking the product's health"}, {ID: productup.StepEdge, Label: "Opening the product on 443"},
	}
}

func (f *phasedProbe) set(r productup.Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.res = r
}

func withPhased(p *phasedProbe) func(*box, *osadmin.Options) {
	return func(_ *box, o *osadmin.Options) {
		o.ProductUp = p
		o.Upgrade.ProductUpEvery = 5 * time.Millisecond
	}
}

func applyPhased(t *testing.T, p *phasedProbe, opts ...func(*box, *osadmin.Options)) (*box, *browser) {
	t.Helper()
	return applyProductOpts(t, append([]func(*box, *osadmin.Options){withPhased(p)}, opts...)...)
}

const phasedHead = "verify:DONE stage:DONE switch:DONE restart:DONE "

// A phased product's apply shows the slot's own steps once it restarts:
// the box's quiesce and cluster steps, then one per phase.
func TestAPhasedApplyShowsEachPhase(t *testing.T) {
	p := &phasedProbe{res: productup.Result{Step: "phase:data", Detail: "Applying app-data", Timeout: time.Minute}}
	_, alice := applyPhased(t, p)
	got := waitSteps(t, alice, phasedHead+"k0s:DONE images:DONE quiesce:DONE cluster:DONE phase:data:ACTIVE phase:front:PENDING product_health:PENDING edge:PENDING")
	if s := step(t, got, "phase:data"); s.GetLabel() != "Starting the database" || s.GetDetail() != "Applying app-data" {
		t.Fatalf("the data step %+v", s)
	}
	p.set(productup.Result{})
	waitSteps(t, alice, phasedHead+"k0s:DONE images:DONE quiesce:DONE cluster:DONE phase:data:DONE phase:front:DONE product_health:DONE edge:DONE")
}

// A phase that isn't Ready within its own timeout fails the apply there:
// the step names what it waited for, the code is UPGRADE_PRODUCT_START,
// and the box says failed, with the phase and the reason, so 443 never
// serves a half-started product.
func TestAPhaseThatTimesOutFailsTheApply(t *testing.T) {
	p := &phasedProbe{res: productup.Result{Step: "phase:front", Detail: "0 of 1 pods ready: app/web-0 CrashLoopBackOff", Timeout: time.Minute}}
	e := &fakeEdge{}
	b, alice := applyPhased(t, p, withEdge(e))
	b.finishSetup()
	waitSteps(t, alice, phasedHead+"k0s:DONE images:DONE quiesce:DONE cluster:DONE phase:data:DONE phase:front:ACTIVE product_health:PENDING edge:PENDING")
	b.clk.Advance(2 * time.Minute)
	alice = b.browser()
	alice.signIn("alice")
	got := waitSteps(t, alice, phasedHead+"k0s:DONE images:DONE quiesce:DONE cluster:DONE phase:data:DONE phase:front:FAILED product_health:PENDING edge:PENDING")
	if got.GetInProgress() || !got.GetFailed() || got.GetCode() != "UPGRADE_PRODUCT_START" {
		t.Fatalf("failed %+v", got)
	}
	if d := step(t, got, "phase:front").GetDetail(); !strings.Contains(d, "app/web-0 CrashLoopBackOff") {
		t.Fatalf("detail %q", d)
	}
	b.waitState(boxstate.Failed)
	deadline := time.Now().Add(5 * time.Second)
	for {
		ph := e.phases()
		if n := len(ph); n > 0 && ph[n-1].State == string(boxstate.Failed) {
			if d := ph[n-1].Detail; !strings.Contains(d, "Starting the web apps") || !strings.Contains(d, "CrashLoopBackOff") {
				t.Fatalf("the pushed detail %q", d)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no failed push: %+v", e.phases())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A phase whose pod can never start fails at once, without waiting for
// its timeout.
func TestAPhaseThatCantStartFailsAtOnce(t *testing.T) {
	p := &phasedProbe{res: productup.Result{Step: "phase:data", Detail: "0 of 1 pods ready: app/db-0 ErrImageNeverPull", Timeout: time.Hour, Failed: true}}
	b, alice := applyPhased(t, p)
	b.finishSetup()
	waitSteps(t, alice, phasedHead+"k0s:DONE images:DONE quiesce:DONE cluster:DONE phase:data:FAILED phase:front:PENDING product_health:PENDING edge:PENDING")
	b.waitState(boxstate.Failed)
}

// On a boot (no apply) a phase that times out leaves the box failed, not
// running: the product isn't served half started after its bound.
func TestABootWhosePhaseTimesOutSaysFailed(t *testing.T) {
	p := &phasedProbe{res: productup.Result{Step: "phase:data", Detail: "0 of 1 pods ready", Timeout: time.Minute}}
	b := newBox(t, false, withPhased(p))
	b.finishSetup()
	b.installProduct("0.1.0")
	b.setRunning(true)
	if got := b.phase().GetState(); got != string(boxstate.Starting) {
		t.Fatalf("coming up: %q", got)
	}
	time.Sleep(30 * time.Millisecond)
	b.clk.Advance(2 * time.Minute)
	b.waitState(boxstate.Failed)
	// k0s starting again (a reboot, a re-apply) starts over.
	b.setRunning(false)
	if got := b.phase().GetState(); got != string(boxstate.Starting) {
		t.Fatalf("k0s stopped: %q", got)
	}
	p.set(productup.Result{})
	b.setRunning(true)
	b.waitState(boxstate.Running)
}

// While an import holds the product the box says maintenance, and the
// hold never times out or fails.
func TestAnImportHoldSaysMaintenance(t *testing.T) {
	p := &phasedProbe{res: productup.Result{Step: "phase:front", Detail: "Held while an import is open", Held: true}}
	b := newBox(t, false, withPhased(p))
	b.finishSetup()
	b.installProduct("0.1.0")
	b.setRunning(true)
	b.waitState(boxstate.Maintenance)
	b.clk.Advance(osadmin.ProductUpBound + time.Hour)
	time.Sleep(30 * time.Millisecond)
	b.waitState(boxstate.Maintenance)
	p.set(productup.Result{})
	b.waitState(boxstate.Running)
}

func applyProductOpts(t *testing.T, opts ...func(*box, *osadmin.Options)) (*box, *browser) {
	t.Helper()
	b := newBox(t, false, opts...)
	alice := b.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	return b, alice
}

// Opening an import on a running product asks the product again, so a
// phased one is held (maintenance) while it's open; closing it asks again,
// and the held phases come back before the box says running.
func TestOpeningAndClosingAnImportAsksTheProductAgain(t *testing.T) {
	p := &phasedProbe{}
	ib := newImportBox(t, withPhased(p))
	b := ib.b
	b.finishSetup()
	b.setRunning(true)
	b.waitState(boxstate.Running)
	ctx := context.Background()
	alice := b.browser()
	alice.signIn("alice")
	alice.stepUp("alice")
	ic := osadminv1connect.NewImportServiceClient(alice.hc, b.ts.URL)
	p.set(productup.Result{Step: "phase:front", Detail: "Held while an import is open", Held: true})
	if _, err := ic.OpenImport(ctx, connect.NewRequest(&osadminv1.OpenImportRequest{})); err != nil {
		t.Fatal(err)
	}
	b.waitState(boxstate.Maintenance)
	p.set(productup.Result{Step: "phase:front", Detail: "1 of 2 pods ready", Timeout: time.Minute})
	if _, err := ic.CloseImport(ctx, connect.NewRequest(&osadminv1.CloseImportRequest{})); err != nil {
		t.Fatal(err)
	}
	b.waitState(boxstate.Starting)
	p.set(productup.Result{})
	b.waitState(boxstate.Running)
}
