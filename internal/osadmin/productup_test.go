// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

// fakeProbe answers the step the test sets.
type fakeProbe struct {
	mu     sync.Mutex
	step   string
	detail string
	err    error
	asks   int
}

func (f *fakeProbe) Check(context.Context) (productup.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asks++
	return productup.Result{Step: f.step, Detail: f.detail}, f.err
}

func (f *fakeProbe) set(step, detail string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.step, f.detail, f.err = step, detail, err
}

func withProbe(p *fakeProbe) func(*box, *osadmin.Options) {
	return func(_ *box, o *osadmin.Options) {
		o.ProductUp = p
		o.Upgrade.ProductUpEvery = 5 * time.Millisecond
	}
}

// waitSteps polls the progress until want, or fails after a few seconds.
func waitSteps(t *testing.T, br *browser, want string) *osadminv1.UpgradeProgress {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		p := br.progress(t)
		if steps(p) == want {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatalf("steps %s, want %s", steps(p), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func applyProductWith(t *testing.T, p *fakeProbe) (*box, *browser) {
	t.Helper()
	b := newBox(t, false, withProbe(p))
	alice := b.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if got := steps(alice.progress(t)); got != "verify:DONE stage:DONE switch:PENDING restart:PENDING k0s:PENDING images:PENDING manifests:PENDING pods:PENDING edge:PENDING" {
		t.Fatalf("staged: %s", got)
	}
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	return b, alice
}

// After the restart, a product apply follows the product coming up, step
// by step, until the product answers on 443: the apply stays in progress
// meanwhile, so Updates and the console show where it is.
func TestAProductApplyFollowsTheProductComingUp(t *testing.T) {
	p := &fakeProbe{step: productup.StepK0s, detail: "The Kubernetes API doesn't answer yet."}
	_, alice := applyProductWith(t, p)
	got := waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:ACTIVE images:PENDING manifests:PENDING pods:PENDING edge:PENDING")
	if !got.GetInProgress() || got.GetFailed() {
		t.Fatalf("coming up %+v", got)
	}
	if d := step(t, got, "k0s").GetDetail(); d != "The Kubernetes API doesn't answer yet." {
		t.Fatalf("detail %q", d)
	}
	p.set(productup.StepPods, "2 of 5 pods ready", nil)
	got = waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE pods:ACTIVE edge:PENDING")
	if d := step(t, got, "pods").GetDetail(); d != "2 of 5 pods ready" {
		t.Fatalf("detail %q", d)
	}
	// A pod that falls over again takes the record back to it, never
	// leaving a later step active.
	p.set(productup.StepEdge, "", nil)
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE pods:DONE edge:ACTIVE")
	p.set(productup.StepPods, "4 of 5 pods ready", nil)
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE pods:ACTIVE edge:PENDING")
	// A probe that fails leaves the step where it was.
	p.set("", "", errors.New("k0s kubectl: exit status 1"))
	time.Sleep(30 * time.Millisecond)
	if got := steps(alice.progress(t)); got != "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE pods:ACTIVE edge:PENDING" {
		t.Fatalf("after a failed probe: %s", got)
	}
	p.set("", "", nil)
	got = waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE pods:DONE edge:DONE")
	if got.GetInProgress() || got.GetFailed() {
		t.Fatalf("up %+v", got)
	}
}

// The public GetPhase carries the coming-up steps too, for the console
// and the restart page before anyone signs in.
func TestThePhaseCarriesTheProductComingUp(t *testing.T) {
	p := &fakeProbe{step: productup.StepImages, detail: "3 of 7 images imported"}
	b, alice := applyProductWith(t, p)
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:ACTIVE manifests:PENDING pods:PENDING edge:PENDING")
	ph, err := osadminv1connect.NewStatusServiceClient(b.browser().hc, b.ts.URL).GetPhase(context.Background(), connect.NewRequest(&osadminv1.GetPhaseRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := steps(ph.Msg.GetUpgradeProgress()); got != "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:ACTIVE manifests:PENDING pods:PENDING edge:PENDING" {
		t.Fatalf("phase %s", got)
	}
}

// A product that doesn't come up within ProductUpBound fails at the step
// it was on, with UPGRADE_PRODUCT_START, and stops being in progress.
func TestAProductThatNeverComesUpFails(t *testing.T) {
	p := &fakeProbe{step: productup.StepPods, detail: "1 of 5 pods ready"}
	b, alice := applyProductWith(t, p)
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE pods:ACTIVE edge:PENDING")
	b.clk.Advance(osadmin.ProductUpBound + time.Minute)
	alice = b.browser()
	alice.signIn("alice")
	got := waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE pods:FAILED edge:PENDING")
	if got.GetInProgress() || !got.GetFailed() || got.GetCode() != "UPGRADE_PRODUCT_START" {
		t.Fatalf("failed %+v", got)
	}
}

// An accessd restart in the middle of the coming up picks it up again,
// instead of failing it as cut off.
func TestARestartResumesFollowingTheProduct(t *testing.T) {
	p := &fakeProbe{step: productup.StepManifests}
	b, alice := applyProductWith(t, p)
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:ACTIVE pods:PENDING edge:PENDING")
	after := newBox(t, false, withProbe(p))
	rec, err := os.ReadFile(filepath.Join(b.state, "osadmin-api", "upgrade-progress.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(after.state, "osadmin-api"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(after.state, "osadmin-api", "upgrade-progress.json"), rec, 0o600); err != nil {
		t.Fatal(err)
	}
	owner := after.browser()
	owner.signIn("alice")
	if got := steps(owner.progress(t)); got != "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:ACTIVE pods:PENDING edge:PENDING" {
		t.Fatalf("after the restart: %s", got)
	}
	after.srv.ResumeProductUp()
	p.set("", "", nil)
	waitSteps(t, owner, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE pods:DONE edge:DONE")
}
