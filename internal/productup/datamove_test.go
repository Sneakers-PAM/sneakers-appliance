// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productup_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/datamove"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

const movingProduct = `format: 2
switches:
  - {name: mcp, label: The MCP server, stacks: [app-mcp]}
phases:
  - {name: data, label: Starting the database, stack: app-data, workloads: [app-db, app-db-new], timeout: 3m}
  - {name: front, label: Starting the web app, stack: app-front, workloads: [app-web, app-mcp], switch_stacks: [app-mcp]}
data_move:
  label: Moving the database
  after: data
  databases: [app]
  source: {namespace: app, name: app-db, host: 127.0.0.1, user: postgres}
  target: {namespace: app, name: app-db-new, host: app-db-new.app.svc, sslmode: require, user: postgres}
`

type fakeMover struct {
	status    datamove.Status
	asked     int
	svc       datamove.Services
	unsettled bool
	settled   int
	failed    []string
	again     int
	reverted  bool
	onOld     bool
	onNew     bool
	tidied    int
	removed   string
}

func (f *fakeMover) Ask(_ productspec.DataMove, svc datamove.Services) datamove.Status {
	f.asked++
	f.svc = svc
	return f.status
}
func (f *fakeMover) Unsettled(productspec.DataMove) bool { return f.unsettled }
func (f *fakeMover) Settle(productspec.DataMove) error   { f.settled++; return nil }
func (f *fakeMover) Fail(_ productspec.DataMove, why string) error {
	f.failed = append(f.failed, why)
	return nil
}
func (f *fakeMover) Again() { f.again++ }
func (f *fakeMover) RecordRevert(holds func(string) bool) (bool, error) {
	f.onOld, f.onNew = holds("app-db"), holds("app-db-new")
	return f.reverted, nil
}
func (f *fakeMover) Tidy(holds func(string) bool) { f.tidied++; f.onNew = holds("app-db-new") }
func (f *fakeMover) KeptDumps() ([]datamove.KeptDump, error) {
	return []datamove.KeptDump{{Name: "replaced-20261101T120000Z"}}, nil
}
func (f *fakeMover) RemoveKept(name string) error { f.removed = name; return nil }

func movingProbe(t *testing.T, c *fakeCluster, m productup.DataMover) (*productup.Probe, string) {
	t.Helper()
	p, manifests := phasedProbe(t, c)
	if err := os.WriteFile(filepath.Join(p.Slot, productspec.File), []byte(movingProduct), 0o644); err != nil {
		t.Fatal(err)
	}
	if m != nil {
		p.Move = m
	}
	return p, manifests
}

// upToTheMove brings the fake cluster to the data phase being Ready.
func upToTheMove(t *testing.T, c *fakeCluster, p *productup.Probe, m *fakeMover) productup.Result {
	t.Helper()
	c.apiUp = true
	ctx := context.Background()
	var r productup.Result
	for range 30 {
		var err error
		if r, err = p.Check(ctx); err != nil {
			t.Fatal(err)
		}
		if r.Step == productup.StepDataMove || r.Step == "phase:front" {
			return r
		}
		k0sApplies(t, c, p)
	}
	t.Fatalf("never reached the move: %+v (asked %d)", r, m.asked)
	return r
}

// k0sApplies does what k0s does with the stacks in front of it: the ones
// the box placed, and the always-on ones.
func k0sApplies(t *testing.T, c *fakeCluster, p *productup.Probe) {
	t.Helper()
	for _, st := range []string{"app", "edge"} {
		c.apply(t, p.Slot, st)
	}
	c.setReady("Deployment edge/edge", true, "")
	if _, err := os.Stat(filepath.Join(p.Manifests, "app-data")); err == nil {
		c.apply(t, p.Slot, "app-data")
		c.setReady("StatefulSet app/app-db", true, "")
	}
}

func TestAMoveIsAStepAfterItsPhase(t *testing.T) {
	p, _ := movingProbe(t, newCluster(), &fakeMover{})
	var ids []string
	label := ""
	for _, s := range p.Steps() {
		ids = append(ids, s.ID)
		if s.ID == productup.StepDataMove {
			label = s.Label
		}
	}
	i := slices.Index(ids, "phase:data")
	if i < 0 || ids[i+1] != productup.StepDataMove || ids[i+2] != "phase:front" {
		t.Fatalf("steps %v", ids)
	}
	if label != "Moving the database" {
		t.Fatalf("label %q", label)
	}
	if !productup.IsStep(productup.StepDataMove) {
		t.Fatal("IsStep")
	}
}

func TestTheLaterPhasesWaitForTheMove(t *testing.T) {
	c := newCluster()
	m := &fakeMover{status: datamove.Status{Detail: "Restoring app (1 of 1)"}}
	p, manifests := movingProbe(t, c, m)
	r := upToTheMove(t, c, p, m)
	if r.Step != productup.StepDataMove || r.Detail != "Restoring app (1 of 1)" || r.Failed || !r.Unbounded || r.Timeout != 0 {
		t.Fatalf("%+v", r)
	}
	if slices.Contains(placed(t, manifests), "app-front") {
		t.Fatal("a later phase was placed during the move")
	}
	m.status = datamove.Status{Done: true}
	r, err := p.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Step != "phase:front" || r.Unbounded {
		t.Fatalf("%+v", r)
	}
	if !slices.Contains(placed(t, manifests), "app-front") {
		t.Fatal("the next phase wasn't placed after the move")
	}
}

func TestAFailedMoveStopsTheProductThere(t *testing.T) {
	c := newCluster()
	m := &fakeMover{status: datamove.Status{Failed: true, Detail: "restore: boom"}}
	p, manifests := movingProbe(t, c, m)
	r := upToTheMove(t, c, p, m)
	if r.Step != productup.StepDataMove || !r.Failed || r.Detail != "restore: boom" {
		t.Fatalf("%+v", r)
	}
	if slices.Contains(placed(t, manifests), "app-front") {
		t.Fatal("a later phase was placed after a failed move")
	}
}

func TestAMoveTheProbeCannotRunIsAnError(t *testing.T) {
	c := newCluster()
	p, _ := movingProbe(t, c, nil)
	c.apiUp = true
	for range 30 {
		_, err := p.Check(context.Background())
		if err != nil {
			if !strings.Contains(err.Error(), "data move") {
				t.Fatal(err)
			}
			return
		}
		k0sApplies(t, c, p)
	}
	t.Fatal("no error")
}

func TestTheMovesServicesStopWhatRunsInTheLaterPhases(t *testing.T) {
	c := newCluster()
	m := &fakeMover{status: datamove.Status{Detail: "x"}}
	p, _ := movingProbe(t, c, m)
	upToTheMove(t, c, p, m)
	c.apply(t, p.Slot, "app-front")
	c.setReady("Deployment app/app-web", true, "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.svc.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if w := c.workloads["Deployment app/app-web"]; w == nil || w.replicas != 0 {
		t.Fatalf("%+v", w)
	}
	if got := c.callsMatching("scale "); len(got) == 0 {
		t.Fatal("nothing scaled")
	}
	if err := m.svc.Start(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestTheProbePassesSettlingOnToTheMove(t *testing.T) {
	m := &fakeMover{unsettled: true}
	p, _ := movingProbe(t, newCluster(), m)
	if !p.MoveUnsettled() {
		t.Fatal("unsettled")
	}
	if err := p.MoveFailed("the gateway failed"); err != nil {
		t.Fatal(err)
	}
	if err := p.SettleMove(); err != nil {
		t.Fatal(err)
	}
	p.MoveAgain()
	if m.settled != 1 || m.again != 1 || !slices.Equal(m.failed, []string{"the gateway failed"}) {
		t.Fatalf("%+v", m)
	}
}

func TestASlotWithoutAMoveHasNothingToSettle(t *testing.T) {
	m := &fakeMover{unsettled: true}
	p, _ := phasedProbe(t, newCluster())
	p.Move = m
	if p.MoveUnsettled() {
		t.Fatal("the slot declares no move")
	}
	if err := p.MoveFailed("x"); err != nil {
		t.Fatal(err)
	}
	if err := p.SettleMove(); err != nil {
		t.Fatal(err)
	}
	if m.settled != 0 || len(m.failed) != 0 {
		t.Fatalf("%+v", m)
	}
}

// What's recorded of a revert is judged by the slot now current, whether it
// declares a move or not: the slot gone back to usually doesn't.
func TestTheProbeAsksTheCurrentSlotWhetherItHoldsTheTarget(t *testing.T) {
	m := &fakeMover{reverted: true}
	p, _ := movingProbe(t, newCluster(), m)
	if ok, err := p.RecordMoveRevert(); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if !m.onNew || !m.onOld {
		t.Fatalf("%+v", m)
	}
	p, _ = phasedProbe(t, newCluster())
	p.Move = m
	if ok, err := p.RecordMoveRevert(); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if m.onNew {
		t.Fatal("a slot without the target holds it")
	}
	p.TidyMove()
	if m.tidied != 1 || m.onNew {
		t.Fatalf("%+v", m)
	}
}

// A slot that can't be read says nothing about where the box is.
func TestASlotThatCannotBeReadRecordsNothing(t *testing.T) {
	m := &fakeMover{reverted: true}
	p, _ := phasedProbe(t, newCluster())
	p.Move = m
	p.Slot = filepath.Join(t.TempDir(), "gone")
	if ok, err := p.RecordMoveRevert(); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	p.TidyMove()
	if m.tidied != 0 {
		t.Fatalf("%+v", m)
	}
}

func TestTheProbePassesKeptDumpsOnToTheMove(t *testing.T) {
	m := &fakeMover{}
	p, _ := phasedProbe(t, newCluster())
	p.Move = m
	list, err := p.KeptDumps()
	if err != nil || len(list) != 1 {
		t.Fatalf("%+v %v", list, err)
	}
	if err := p.RemoveKeptDump("replaced-20261101T120000Z"); err != nil || m.removed == "" {
		t.Fatalf("%v %+v", err, m)
	}
}
