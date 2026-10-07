// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package setup_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/setup"
)

// disks are the tmpfs and the state volume.
type disks struct {
	t          *testing.T
	run, state string
}

func newDisks(t *testing.T) disks {
	return disks{t: t, run: t.TempDir(), state: t.TempDir()}
}

func (d disks) paths() setup.Paths { return setup.Paths{Tmp: d.run, State: d.state} }

// powerCut loses the tmpfs; the state volume stays.
func (d disks) powerCut() disks {
	d.t.Helper()
	if err := os.RemoveAll(d.run); err != nil {
		d.t.Fatal(err)
	}
	d.run = d.t.TempDir()
	return d
}

func open(t *testing.T, d disks) *setup.Machine {
	t.Helper()
	m, err := setup.Open(d.paths())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func mustComplete(t *testing.T, m *setup.Machine, s setup.Step) {
	t.Helper()
	if err := m.Complete(s); err != nil {
		t.Fatalf("complete %s: %v", s, err)
	}
}

// The steps run in order, each once; resuming after a power cut picks up
// at the first step not done; before the protection step the progress is
// on the tmpfs only, so a cut there runs the network step again.
func TestStepOrderAndResume(t *testing.T) {
	d := newDisks(t)
	m := open(t, d)
	if m.Next() != setup.StepNetwork {
		t.Fatalf("next %s", m.Next())
	}
	err := m.Complete(setup.StepAdmin)
	if !codes.Is(err, codes.SetupIncomplete) {
		t.Fatalf("admin before network: %v", err)
	}
	mustComplete(t, m, setup.StepNetwork)
	if _, err := os.Stat(filepath.Join(d.state, setup.ProgressFile)); !os.IsNotExist(err) {
		t.Fatal("the progress reached the state volume before the protection step")
	}
	d = d.powerCut()
	m = open(t, d)
	if m.Next() != setup.StepNetwork {
		t.Fatalf("after a cut before protection: %s", m.Next())
	}
	mustComplete(t, m, setup.StepNetwork)
	mustComplete(t, m, setup.StepProtection)
	if _, err := os.Stat(filepath.Join(d.run, setup.ProgressFile)); !os.IsNotExist(err) {
		t.Fatal("the tmpfs copy stayed after the protection step")
	}
	d = d.powerCut()
	m = open(t, d)
	if m.Next() != setup.StepAdmin || !m.Done(setup.StepNetwork) || !m.Done(setup.StepProtection) {
		t.Fatalf("after a cut past protection: next %s", m.Next())
	}
	for _, s := range []setup.Step{setup.StepAdmin, setup.StepRecovery, setup.StepSignIn, setup.StepDone} {
		mustComplete(t, m, s)
		d = d.powerCut()
		m = open(t, d)
		if !m.Done(s) {
			t.Fatalf("%s lost in a cut", s)
		}
	}
	if m.Next() != "" {
		t.Fatalf("next after done: %q", m.Next())
	}
	if err := m.Complete(setup.StepDone); !codes.Is(err, codes.SetupIncomplete) {
		t.Fatalf("done twice: %v", err)
	}
}

// accessd reads the progress for its invariants: no owner with a key is
// required before the admin step, no recovery key before the recovery
// step.
func TestReadProgressForTheInvariants(t *testing.T) {
	d := newDisks(t)
	p := setup.ReadProgress(d.paths())
	if p.Done(setup.StepAdmin) || p.Done(setup.StepRecovery) {
		t.Fatal("a fresh box is past a step")
	}
	m := open(t, d)
	for _, s := range []setup.Step{setup.StepNetwork, setup.StepProtection, setup.StepAdmin} {
		mustComplete(t, m, s)
	}
	p = setup.ReadProgress(d.paths())
	if !p.Done(setup.StepAdmin) || p.Done(setup.StepRecovery) {
		t.Fatalf("%+v", p)
	}
}

// A progress file that doesn't parse stops the machine instead of running
// steps again on a box that may be set up.
func TestABrokenProgressFileIsAnError(t *testing.T) {
	d := newDisks(t)
	if err := os.WriteFile(filepath.Join(d.state, setup.ProgressFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Open(d.paths()); err == nil {
		t.Fatal("opened a broken progress file")
	}
}
