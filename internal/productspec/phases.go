// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Phase is one step of bringing the product up (docs/upgrades.md#the-phases):
// the box places the phase's stacks, waits until every workload in them
// runs the slot's version and is Ready, and only then goes on to the next
// phase. On every boot, update and revert the product comes up phase by
// phase in the order product.yaml lists them; it stops in the reverse
// order.
type Phase struct {
	// Name is a lower-case word; the progress step is "phase:<name>".
	Name string `yaml:"name"`
	// Label is the step's words in Updates, the console and the box-state
	// stream.
	Label string `yaml:"label"`
	// Stack is the phase's own k0s stack: the bundle render puts the
	// phase's workloads in it, and nothing else.
	Stack string `yaml:"stack"`
	// Workloads are the Deployments and StatefulSets of the phase, by
	// name. The render refuses a workload no phase names, and labels each
	// with its phase (PhaseLabel, PhaseOrderLabel).
	Workloads []string `yaml:"workloads"`
	// SwitchStacks are switch-gated stacks placed with the phase, before
	// its own stack, while their switch is on.
	SwitchStacks []string `yaml:"switch_stacks"`
	// Timeout is how long the phase may take to be Ready; empty is
	// DefaultPhaseTimeout.
	Timeout string `yaml:"timeout"`
}

// The bounds and the default of a phase's timeout.
const (
	DefaultPhaseTimeout = 5 * time.Minute
	MinPhaseTimeout     = time.Minute
	MaxPhaseTimeout     = time.Hour
)

// The labels the bundle render puts on each phased workload and its pod
// template: the phase's name and its place in the order, from 1. The box
// stops the product by them, latest phase first, so it needs no slot
// files to do it (on an update the slot has switched by then).
const (
	PhaseLabel      = "sneakers-appliance/phase"
	PhaseOrderLabel = "sneakers-appliance/phase-order"
)

// PhaseStacksFile is written into the slot next to the bundle: one line
// per phase stack, "<order> <phase> <stack>", in the order they're placed,
// for k0s-interim, which leaves them to the box's phase loop.
const PhaseStacksFile = "phase-stacks"

// TimeoutOrDefault is the phase's timeout.
func (p Phase) TimeoutOrDefault() time.Duration {
	if p.Timeout == "" {
		return DefaultPhaseTimeout
	}
	d, _ := time.ParseDuration(p.Timeout)
	return d
}

// Stacks are the phase's stacks in the order they're placed: its switch
// stacks, then its own.
func (p Phase) Stacks() []string {
	return append(slices.Clone(p.SwitchStacks), p.Stack)
}

// PhaseStacks are every phase's stacks, in the order they're placed.
func (s Spec) PhaseStacks() []string {
	var out []string
	for _, p := range s.Phases {
		out = append(out, p.Stacks()...)
	}
	return out
}

// PhaseOf is the index of the phase that names workload.
func (s Spec) PhaseOf(workload string) (int, bool) {
	for i, p := range s.Phases {
		if slices.Contains(p.Workloads, workload) {
			return i, true
		}
	}
	return 0, false
}

func (s Spec) checkPhases() error {
	switched := map[string]bool{}
	for _, w := range s.Switches {
		for _, st := range w.Stacks {
			switched[st] = true
		}
	}
	importStack, _ := s.ImportStack()
	names, stacks, workloads := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, p := range s.Phases {
		if !nameRE.MatchString(p.Name) || names[p.Name] {
			return bad("phases[%d]: %q isn't a lower-case word, or is declared twice", i, p.Name)
		}
		names[p.Name] = true
		if strings.TrimSpace(p.Label) == "" {
			return bad("phases[%d]: %s has no label", i, p.Name)
		}
		if !stackRE.MatchString(p.Stack) || stacks[p.Stack] || switched[p.Stack] || p.Stack == RBACStack || p.Stack == BoxSecretsStack {
			return bad("phases[%d]: the stack %q isn't a stack name of the phase's own", i, p.Stack)
		}
		stacks[p.Stack] = true
		if len(p.Workloads) == 0 {
			return bad("phases[%d]: %s names no workload", i, p.Name)
		}
		for _, w := range p.Workloads {
			if !dnsRE.MatchString(w) || workloads[w] {
				return bad("phases[%d]: the workload %q isn't a name, or another phase names it", i, w)
			}
			workloads[w] = true
		}
		for _, st := range p.SwitchStacks {
			if !switched[st] || stacks[st] || st == importStack {
				return bad("phases[%d]: %q isn't a switch's stack, is placed by another phase, or is the import's", i, st)
			}
			stacks[st] = true
		}
		if t := p.Timeout; t != "" {
			d, err := time.ParseDuration(t)
			if err != nil || d < MinPhaseTimeout || d > MaxPhaseTimeout {
				return bad("phases[%d]: the timeout %q isn't a duration from %s to %s", i, t, MinPhaseTimeout, MaxPhaseTimeout)
			}
		}
	}
	return nil
}

func writePhaseStacks(dir string, s Spec) error {
	p := filepath.Join(dir, PhaseStacksFile)
	if len(s.Phases) == 0 {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("productspec: %w", err)
		}
		return nil
	}
	var b strings.Builder
	for i, ph := range s.Phases {
		for _, st := range ph.Stacks() {
			fmt.Fprintf(&b, "%d %s %s\n", i+1, ph.Name, st)
		}
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil { // #nosec G306 -- stack names, nothing secret
		return fmt.Errorf("productspec: %w", err)
	}
	return nil
}
