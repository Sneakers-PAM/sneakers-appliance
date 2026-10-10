// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	if got := steps(alice.progress(t)); got != "verify:DONE stage:DONE switch:PENDING restart:PENDING k0s:PENDING images:PENDING manifests:PENDING cluster_dns:PENDING pods:PENDING product_health:PENDING edge:PENDING" {
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
	got := waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:ACTIVE images:PENDING manifests:PENDING cluster_dns:PENDING pods:PENDING product_health:PENDING edge:PENDING")
	if !got.GetInProgress() || got.GetFailed() {
		t.Fatalf("coming up %+v", got)
	}
	if d := step(t, got, "k0s").GetDetail(); d != "The Kubernetes API doesn't answer yet." {
		t.Fatalf("detail %q", d)
	}
	p.set(productup.StepPods, "2 of 5 pods ready", nil)
	got = waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:ACTIVE product_health:PENDING edge:PENDING")
	if d := step(t, got, "pods").GetDetail(); d != "2 of 5 pods ready" {
		t.Fatalf("detail %q", d)
	}
	// A pod that falls over again takes the record back to it, never
	// leaving a later step active.
	p.set(productup.StepEdge, "", nil)
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:DONE product_health:DONE edge:ACTIVE")
	p.set(productup.StepPods, "4 of 5 pods ready", nil)
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:ACTIVE product_health:PENDING edge:PENDING")
	// A probe that fails leaves the step where it was.
	p.set("", "", errors.New("k0s kubectl: exit status 1"))
	time.Sleep(30 * time.Millisecond)
	if got := steps(alice.progress(t)); got != "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:ACTIVE product_health:PENDING edge:PENDING" {
		t.Fatalf("after a failed probe: %s", got)
	}
	p.set("", "", nil)
	got = waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:DONE product_health:DONE edge:DONE")
	if got.GetInProgress() || got.GetFailed() {
		t.Fatalf("up %+v", got)
	}
}

// The public GetPhase carries the coming-up steps too, for the console
// and the restart page before anyone signs in.
func TestThePhaseCarriesTheProductComingUp(t *testing.T) {
	p := &fakeProbe{step: productup.StepImages, detail: "3 of 7 images imported"}
	b, alice := applyProductWith(t, p)
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:ACTIVE manifests:PENDING cluster_dns:PENDING pods:PENDING product_health:PENDING edge:PENDING")
	ph, err := osadminv1connect.NewStatusServiceClient(b.browser().hc, b.ts.URL).GetPhase(context.Background(), connect.NewRequest(&osadminv1.GetPhaseRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if got := steps(ph.Msg.GetUpgradeProgress()); got != "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:ACTIVE manifests:PENDING cluster_dns:PENDING pods:PENDING product_health:PENDING edge:PENDING" {
		t.Fatalf("phase %s", got)
	}
}

// A product that doesn't come up within ProductUpBound fails at the step
// it was on, with UPGRADE_PRODUCT_START, and stops being in progress.
func TestAProductThatNeverComesUpFails(t *testing.T) {
	p := &fakeProbe{step: productup.StepPods, detail: "1 of 5 pods ready"}
	b, alice := applyProductWith(t, p)
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:ACTIVE product_health:PENDING edge:PENDING")
	b.clk.Advance(osadmin.ProductUpBound + time.Minute)
	alice = b.browser()
	alice.signIn("alice")
	got := waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:FAILED product_health:PENDING edge:PENDING")
	if got.GetInProgress() || !got.GetFailed() || got.GetCode() != "UPGRADE_PRODUCT_START" {
		t.Fatalf("failed %+v", got)
	}
}

// An accessd restart in the middle of the coming up picks it up again,
// instead of failing it as cut off.
func TestARestartResumesFollowingTheProduct(t *testing.T) {
	p := &fakeProbe{step: productup.StepManifests}
	b, alice := applyProductWith(t, p)
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:ACTIVE cluster_dns:PENDING pods:PENDING product_health:PENDING edge:PENDING")
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
	if got := steps(owner.progress(t)); got != "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:ACTIVE cluster_dns:PENDING pods:PENDING product_health:PENDING edge:PENDING" {
		t.Fatalf("after the restart: %s", got)
	}
	after.srv.ResumeProductUp()
	p.set("", "", nil)
	waitSteps(t, owner, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:DONE product_health:DONE edge:DONE")
}

// The wait is the installed product.yaml's ready.timeout: past it the
// install fails at the step it was on, with what it waited for, and the
// history records the failure; it never says done.
func TestTheProductsOwnTimeoutFailsTheInstallWithTheReason(t *testing.T) {
	p := &fakeProbe{step: productup.StepPods, detail: "Rolling out (3 of 5 ready): waiting for app/api, 0 of 1 updated, 1 running"}
	b, alice := applyProductWith(t, p)
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:ACTIVE product_health:PENDING edge:PENDING")
	if got := step(t, alice.progress(t), "pods").GetLabel(); got != "Rolling out" {
		t.Fatalf("label %q", got)
	}
	if err := os.WriteFile(filepath.Join(b.state, "product", "current", "product.yaml"), []byte("format: 2\nready:\n  timeout: 2m\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b.clk.Advance(3 * time.Minute)
	alice = b.browser()
	alice.signIn("alice")
	got := waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:FAILED product_health:PENDING edge:PENDING")
	if got.GetInProgress() || !got.GetFailed() || got.GetCode() != "UPGRADE_PRODUCT_START" {
		t.Fatalf("failed %+v", got)
	}
	if d := step(t, got, "pods").GetDetail(); !strings.Contains(d, "isn't ready after 2m0s") || !strings.Contains(d, "waiting for app/api") {
		t.Fatalf("the reason %q", d)
	}
	h := alice.upgrades(t).GetHistory()[0]
	if h.GetAction() != "apply" || h.GetTarget() != product || h.GetOutcome() != "failed" || h.GetCode() != "UPGRADE_PRODUCT_START" || h.GetVersion() != "0.2.0" {
		t.Fatalf("history %+v", h)
	}
}

// A product revert follows the product coming up the same way: it isn't
// done until the probe says the product is ready.
func TestAProductRevertWaitsForTheProduct(t *testing.T) {
	p := &fakeProbe{}
	b, alice := applyProductWith(t, p)
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:DONE product_health:DONE edge:DONE")
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.3.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:DONE product_health:DONE edge:DONE")
	p.set(productup.StepPods, "Rolling out (0 of 1 ready): waiting for app/api, the new version isn't applied yet", nil)
	if _, err := alice.upgrade().RevertUpdate(context.Background(), connect.NewRequest(&osadminv1.RevertUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	got := waitSteps(t, alice, "switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:ACTIVE product_health:PENDING edge:PENDING")
	if got.GetAction() != "revert" || !got.GetInProgress() {
		t.Fatalf("revert %+v", got)
	}
	p.set(productup.StepHealth, "app/api:http /readyz doesn't answer ready yet", nil)
	waitSteps(t, alice, "switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:DONE product_health:ACTIVE edge:PENDING")
	p.set("", "", nil)
	waitSteps(t, alice, "switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:DONE product_health:DONE edge:DONE")
}

// waitHistory polls the history until its latest entry is action, or
// fails after a few seconds.
func waitHistory(t *testing.T, br *browser, action string) *osadminv1.UpgradeEvent {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if h := br.upgrades(t).GetHistory(); len(h) > 0 && h[0].GetAction() == action {
			return h[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("the history never got %s: %v", action, br.upgrades(t).GetHistory())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A product apply goes into the history only once the product is ready:
// while it rolls out the latest entry is still the stage.
func TestAProductApplyIsInTheHistoryOnlyOnceReady(t *testing.T) {
	p := &fakeProbe{step: productup.StepPods, detail: "Rolling out (3 of 5 ready): waiting for app/api, 0 of 1 updated, 1 running"}
	_, alice := applyProductWith(t, p)
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:ACTIVE product_health:PENDING edge:PENDING")
	if h := alice.upgrades(t).GetHistory()[0]; h.GetAction() != "stage" {
		t.Fatalf("the apply is in the history while it rolls out: %+v", h)
	}
	p.set("", "", nil)
	h := waitHistory(t, alice, "apply")
	if h.GetOutcome() != "ok" || h.GetActor() != "alice" || h.GetVersion() != "0.2.0" || h.GetTarget() != product {
		t.Fatalf("history %+v", h)
	}
}

// A product revert to a slot that declares no health check still waits
// for the rollout before it's done and in the history: no health check
// skips only that step.
func TestAProductRevertIsInTheHistoryOnlyOnceReady(t *testing.T) {
	p := &fakeProbe{}
	b, alice := applyProductWith(t, p)
	waitHistory(t, alice, "apply")
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.3.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	waitHistory(t, alice, "apply")
	p.set(productup.StepPods, "Rolling out (16 of 19 ready): waiting for app/api, 0 of 1 updated, 1 running", nil)
	if _, err := alice.upgrade().RevertUpdate(context.Background(), connect.NewRequest(&osadminv1.RevertUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	got := waitSteps(t, alice, "switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:ACTIVE product_health:PENDING edge:PENDING")
	if !got.GetInProgress() {
		t.Fatalf("revert %+v", got)
	}
	time.Sleep(30 * time.Millisecond)
	if h := alice.upgrades(t).GetHistory()[0]; h.GetAction() == "revert" {
		t.Fatalf("the revert is in the history while it rolls out: %+v", h)
	}
	p.set("", "", nil)
	waitSteps(t, alice, "switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE cluster_dns:DONE pods:DONE product_health:DONE edge:DONE")
	if h := waitHistory(t, alice, "revert"); h.GetOutcome() != "ok" || h.GetVersion() != "0.2.0" || h.GetActor() != "alice" {
		t.Fatalf("history %+v", h)
	}
}
