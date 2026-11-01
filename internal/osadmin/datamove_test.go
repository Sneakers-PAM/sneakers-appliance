// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect" // scrub:allow=fqdn -- a Go module path

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/datamove"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

// movingProbe is a phased product with a data move in its slot.
type movingProbe struct {
	*phasedProbe
	mu        sync.Mutex
	unsettled bool
	settled   int
	failed    []string
	again     int
	// reverted is what the next slot switch records.
	reverted bool
	asked    int
	tidied   int
	dumps    []datamove.KeptDump
	removed  []string
}

func (m *movingProbe) RecordMoveRevert() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.asked++
	return m.reverted, nil
}

func (m *movingProbe) TidyMove() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tidied++
}

func (m *movingProbe) KeptDumps() ([]datamove.KeptDump, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dumps, nil
}

func (m *movingProbe) RemoveKeptDump(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removed = append(m.removed, name)
	return nil
}

func (m *movingProbe) tidies() (asked, tidied int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.asked, m.tidied
}

func (m *movingProbe) MoveUnsettled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.unsettled
}

func (m *movingProbe) MoveFailed(why string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failed = append(m.failed, why)
	m.unsettled = false
	return nil
}

func (m *movingProbe) SettleMove() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settled++
	m.unsettled = false
	return nil
}

func (m *movingProbe) MoveAgain() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.again++
}

func (m *movingProbe) counts() (settled, failed, again int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settled, len(m.failed), m.again
}

func withMoving(p *movingProbe) func(*box, *osadmin.Options) {
	return func(_ *box, o *osadmin.Options) {
		o.ProductUp = p
		o.Upgrade.ProductUpEvery = 5 * time.Millisecond
	}
}

// applyOver applies 0.3.0 over an installed 0.2.0, so a previous slot is
// there to go back to.
func applyOver(t *testing.T, p *movingProbe) (*box, *browser) {
	t.Helper()
	b, alice := applyProductOpts(t, withMoving(p))
	waitReady(t, alice)
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.3.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	return b, alice
}

func waitReady(t *testing.T, alice *browser) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		p := alice.upgrades(t).GetUpgradeProgress()
		if p != nil && !p.GetInProgress() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("still coming up: %+v", p)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A new apply may try a failed move again.
func TestANewApplyLetsAFailedMoveTryAgain(t *testing.T) {
	p := &movingProbe{phasedProbe: &phasedProbe{}}
	_, _ = applyOver(t, p)
	if _, _, again := p.counts(); again == 0 {
		t.Fatal("no")
	}
}

// A move that fails takes the box back to the previous slot by itself: the
// old pins, and with them the old cluster and its volume.
func TestAMoveThatFailsReverts(t *testing.T) {
	p := &movingProbe{phasedProbe: &phasedProbe{}}
	b, alice := applyProductOpts(t, withMoving(p))
	waitReady(t, alice)
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.3.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.unsettled = true
	p.mu.Unlock()
	p.set(productup.Result{Step: "phase:data", Detail: "restore: boom", Failed: true, Unbounded: true})
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, failed, _ := p.counts(); failed == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the move was never marked failed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	p.set(productup.Result{})
	h := waitHistory(t, alice, "revert")
	if h.GetOutcome() != "ok" || h.GetVersion() != "0.2.0" || h.GetActor() != "osadmin" {
		t.Fatalf("revert %+v", h)
	}
	if up := alice.upgrades(t).GetProduct().GetInstalledVersion(); up != "0.2.0" {
		t.Fatalf("installed %q", up)
	}
}

// Failing a product whose move has settled goes nowhere: the box is on the
// target for good, and the old data is behind it.
func TestAProductFailureAfterASettledMoveDoesNotRevert(t *testing.T) {
	p := &movingProbe{phasedProbe: &phasedProbe{}}
	b, alice := applyProductOpts(t, withMoving(p))
	waitReady(t, alice)
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.3.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	p.set(productup.Result{Step: "phase:front", Detail: "image missing", Failed: true})
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !alice.upgrades(t).GetUpgradeProgress().GetFailed() {
		if time.Now().After(deadline) {
			t.Fatal("never failed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if h := alice.upgrades(t).GetHistory()[0]; h.GetAction() == "revert" {
		t.Fatalf("reverted %+v", h)
	}
}

// A product that comes up after a move settles it.
func TestAProductThatComesUpSettlesTheMove(t *testing.T) {
	p := &movingProbe{phasedProbe: &phasedProbe{}, unsettled: true}
	_, alice := applyProductOpts(t, withMoving(p))
	waitReady(t, alice)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if settled, _, _ := p.counts(); settled > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("never settled")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A data move takes as long as the data: the product's ready timeout doesn't
// run out under it, and the phases after it get the whole timeout again.
func TestAMoveIsNotHeldToTheProductsReadyBound(t *testing.T) {
	p := &movingProbe{phasedProbe: &phasedProbe{res: productup.Result{Step: "phase:data", Detail: "Restoring", Unbounded: true}}}
	b, alice := applyProductOpts(t, withMoving(p))
	waitSteps(t, alice, phasedHead+"k0s:DONE images:DONE quiesce:DONE cluster:DONE phase:data:ACTIVE phase:front:PENDING product_health:PENDING edge:PENDING")
	b.clk.Advance(osadmin.ProductUpBound + time.Hour)
	time.Sleep(50 * time.Millisecond)
	alice = b.browser()
	alice.signIn("alice")
	if got := alice.upgrades(t).GetUpgradeProgress(); got.GetFailed() {
		t.Fatalf("failed under the bound: %+v", got)
	}
	p.set(productup.Result{Step: "phase:front", Detail: "Starting"})
	waitSteps(t, alice, phasedHead+"k0s:DONE images:DONE quiesce:DONE cluster:DONE phase:data:DONE phase:front:ACTIVE product_health:PENDING edge:PENDING")
	b.clk.Advance(time.Minute)
	time.Sleep(50 * time.Millisecond)
	if got := alice.upgrades(t).GetUpgradeProgress(); got.GetFailed() {
		t.Fatalf("the phases after the move lost their time: %+v", got)
	}
	b.clk.Advance(osadmin.ProductUpBound + time.Minute)
	deadline := time.Now().Add(5 * time.Second)
	for !alice.upgrades(t).GetUpgradeProgress().GetFailed() {
		if time.Now().After(deadline) {
			t.Fatal("the bound stopped applying after the move")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A revert that goes back over a settled move says what that means where
// the revert's outcome is read, and asks the slot it landed on.
func TestARevertOverAMoveSaysWhatHappensToTheWrites(t *testing.T) {
	p := &movingProbe{phasedProbe: &phasedProbe{}}
	b, alice := applyOver(t, p)
	waitReady(t, alice)
	p.mu.Lock()
	p.reverted = true
	p.mu.Unlock()
	if _, err := alice.upgrade().RevertUpdate(context.Background(), connect.NewRequest(&osadminv1.RevertUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	h := waitHistory(t, alice, "revert")
	if !strings.Contains(h.GetDetail(), "stays there") {
		t.Fatalf("%+v", h)
	}
}

// A revert that stays on the target says nothing about writes.
func TestARevertThatStaysOnTheTargetSaysNothing(t *testing.T) {
	p := &movingProbe{phasedProbe: &phasedProbe{}}
	b, alice := applyOver(t, p)
	waitReady(t, alice)
	if _, err := alice.upgrade().RevertUpdate(context.Background(), connect.NewRequest(&osadminv1.RevertUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	if h := waitHistory(t, alice, "revert"); strings.Contains(h.GetDetail(), "stays there") {
		t.Fatalf("%+v", h)
	}
}

// A switch cut off before its revert was recorded is recorded at the next
// start, which also retries whatever couldn't be removed.
func TestAStartRecordsARevertAndTidies(t *testing.T) {
	p := &movingProbe{phasedProbe: &phasedProbe{}}
	b, alice := applyOver(t, p)
	waitReady(t, alice)
	asked, tidied := p.tidies()
	b.srv.ResumeProductUp()
	if a, ti := p.tidies(); a != asked+1 || ti != tidied+1 {
		t.Fatalf("asked %d, tidied %d", a, ti)
	}
}

// A product that's ready tidies: it's what proves the old cluster back after
// a failed attempt.
func TestAProductThatComesUpTidiesTheMove(t *testing.T) {
	p := &movingProbe{phasedProbe: &phasedProbe{}}
	_, alice := applyOver(t, p)
	waitReady(t, alice)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, tidied := p.tidies(); tidied > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("never tidied")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
