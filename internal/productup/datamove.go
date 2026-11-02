// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/datamove"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// StepDataMove is the step of a product's data move, between its phase and
// the next (docs/data-move.md).
const StepDataMove = "data_move"

// StepRestore is a restore of the product's database, ahead of the phases
// (docs/backups.md).
const StepRestore = "restore"

// stopEvery is how often stopping the later phases looks again.
const stopEvery = 2 * time.Second

// DataMover runs the slot's data move; datamove.Runner on the box.
type DataMover interface {
	Ask(spec productspec.DataMove, svc datamove.Services) datamove.Status
	Unsettled(spec productspec.DataMove) bool
	Settle(spec productspec.DataMove) error
	Fail(spec productspec.DataMove, why string) error
	Again()
	RecordRevert(holds func(string) bool) (bool, error)
	Tidy(holds func(string) bool)
	KeptDumps() ([]datamove.KeptDump, error)
	RemoveKept(name string) error
	OwedSource() (string, error)
}

// dataMove moves the phase loop on past the move: done once the data is on
// the target. The move runs behind the loop, so this answers at once.
func (p *Probe) dataMove(spec productspec.Spec) (Result, bool, error) {
	if p.Move == nil {
		return Result{}, false, errors.New("productup: the slot declares a data move and this probe can't run one")
	}
	st := p.Move.Ask(*spec.DataMove, laterPhases{p: p, later: spec.DataMoveLater()})
	if st.Done {
		return Result{}, true, nil
	}
	return Result{Step: StepDataMove, Detail: st.Detail, Failed: st.Failed, Unbounded: true}, false, nil
}

// laterPhases are the services of a move on a phased product: what the
// phases after the move's run. The phase loop never places them before the
// move is through, so Stop usually finds nothing, and starting them is the
// loop's next step.
type laterPhases struct {
	p     *Probe
	later []productspec.Phase
}

// Stop scales whatever runs of the later phases to 0 and waits for its
// pods to go, so nothing writes while the data moves.
func (l laterPhases) Stop(ctx context.Context) error {
	names := map[string]bool{}
	for _, ph := range l.later {
		names[ph.Name] = true
	}
	for {
		live, err := l.p.liveWorkloads(ctx)
		if err != nil {
			return err
		}
		for _, w := range live {
			if names[w.Metadata.Labels[productspec.PhaseLabel]] && replicasOf(w) > 0 {
				if err := l.p.scale(ctx, w.Metadata.Namespace, w.Kind, w.Metadata.Name, 0); err != nil {
					return err
				}
			}
		}
		pods, err := l.p.podItems(ctx)
		if err != nil {
			return err
		}
		left := 0
		for _, it := range pods {
			if names[it.Metadata.Labels[productspec.PhaseLabel]] {
				left++
			}
		}
		if left == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%d pods of the later phases are still there: %w", left, ctx.Err())
		case <-time.After(stopEvery):
		}
	}
}

// Start is the phase loop's: it places the next phase once the move says
// done.
func (laterPhases) Start(context.Context) error { return nil }

// MoveUnsettled is whether the slot's data move has started and the box
// hasn't proven healthy on it, so a failure goes back to the old cluster.
func (p *Probe) MoveUnsettled() bool {
	spec := p.spec()
	return p.Move != nil && spec.DataMove != nil && p.Move.Unsettled(*spec.DataMove)
}

// MoveFailed records that the box goes back from the slot's data move.
func (p *Probe) MoveFailed(why string) error {
	spec := p.spec()
	if p.Move == nil || spec.DataMove == nil {
		return nil
	}
	return p.Move.Fail(*spec.DataMove, why)
}

// SettleMove records the box healthy on the slot's data move.
func (p *Probe) SettleMove() error {
	spec := p.spec()
	if p.Move == nil || spec.DataMove == nil {
		return nil
	}
	return p.Move.Settle(*spec.DataMove)
}

// MoveAgain lets a new apply try a failed data move again.
func (p *Probe) MoveAgain() {
	if p.Move != nil {
		p.Move.Again()
	}
}

// holds is whether the current slot has a workload of that name, or false
// with no slot or an unreadable one: that says nothing about where the box
// is.
func (p *Probe) holds() (func(string) bool, bool) {
	return p.holdsIn(p.Slot)
}

// holdsIn reads a slot's workloads from its stacks as well as its phases: a
// slot without phases names them nowhere else.
func (p *Probe) holdsIn(slot string) (func(string) bool, bool) {
	if _, err := os.Stat(slot); err != nil {
		return nil, false
	}
	spec, err := productspec.Load(slot)
	if err != nil {
		return nil, false
	}
	names := map[string]bool{}
	for _, ph := range spec.Phases {
		for _, w := range ph.Workloads {
			names[w] = true
		}
	}
	dirs, err := os.ReadDir(filepath.Join(slot, "manifests"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, false
	}
	var stacks []string
	for _, d := range dirs {
		if d.IsDir() {
			stacks = append(stacks, d.Name())
		}
	}
	ws, err := p.workloadsIn(slot, stacks)
	if err != nil {
		return nil, false
	}
	for _, w := range ws {
		names[w.name] = true
	}
	return func(name string) bool { return names[name] }, true
}

// RecordMoveRevert records a slot switch that went back over a data move,
// and says whether it did. It asks the slot now current, which may declare
// no move at all.
func (p *Probe) RecordMoveRevert() (bool, error) {
	holds, ok := p.holds()
	if p.Move == nil || !ok {
		return false, nil
	}
	return p.Move.RecordRevert(holds)
}

// TidyMove removes the dumps of a data move that nothing needs any more.
func (p *Probe) TidyMove() {
	if holds, ok := p.holds(); p.Move != nil && ok {
		p.Move.Tidy(holds)
	}
}

// KeptDumps lists the dumps data moves kept of what they replaced.
func (p *Probe) KeptDumps() ([]datamove.KeptDump, error) {
	if p.Move == nil {
		return nil, nil
	}
	return p.Move.KeptDumps()
}

// RemoveKeptDump removes one kept dump.
func (p *Probe) RemoveKeptDump(name string) error {
	if p.Move == nil {
		return errors.New("productup: this probe has no data move")
	}
	return p.Move.RemoveKept(name)
}

// CheckMoveApply refuses the bundle in slot while a return to the new cluster
// is owed, if it would land the box on the new cluster with no move: it
// doesn't declare the move, and the old cluster the services write to isn't in
// it. Those writes would be stranded with no word to anyone. A bundle it can't
// read is refused too, since nothing proves it safe.
func (p *Probe) CheckMoveApply(slot string) error {
	if p.Move == nil {
		return nil
	}
	source, err := p.Move.OwedSource()
	if err != nil {
		return codes.Wrap(codes.DataMoveBundle, err)
	}
	if source == "" {
		return nil
	}
	holds, ok := p.holdsIn(slot)
	if !ok {
		return codes.New(codes.DataMoveBundle, "the box reverted over a data move and runs on %s, and this bundle can't be read to see whether it keeps that database; nothing was changed", source)
	}
	spec, err := productspec.Load(slot)
	if err != nil {
		return codes.Wrap(codes.DataMoveBundle, err)
	}
	if spec.DataMove != nil || holds(source) {
		return nil
	}
	return codes.New(codes.DataMoveBundle, "the box reverted over a data move and runs on %s, and this bundle has neither a data_move nor that database, so what was written there since would be stranded; nothing was changed. Apply a bundle that declares data_move, or one that still has %s", source, source)
}
