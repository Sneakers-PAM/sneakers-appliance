// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wizard

import (
	"context"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/setup"
)

// Steps is first boot's progress: which steps are done, and the move to
// normal operation at the end.
type Steps interface {
	Done(ctx context.Context, s Step) (bool, error)
	Complete(ctx context.Context, s Step) error
	// Handover moves the box to normal operation without a restart.
	Handover(ctx context.Context) error
}

var machineSteps = map[Step]setup.Step{
	StepNetwork: setup.StepNetwork, StepProtection: setup.StepProtection, StepAdmin: setup.StepAdmin,
	StepRecovery: setup.StepRecovery, StepSignIn: setup.StepSignIn, StepDone: setup.StepDone,
}

// MachineSteps is the step machine's progress (internal/setup), kept in
// its progress file so a power cut resumes at the first step not done.
type MachineSteps struct{ M *setup.Machine }

// Done reports whether s is done.
func (m MachineSteps) Done(_ context.Context, s Step) (bool, error) {
	return m.M.Done(machineSteps[s]), nil
}

// Complete marks s done, in order.
func (m MachineSteps) Complete(_ context.Context, s Step) error { return m.M.Complete(machineSteps[s]) }

// Handover answers NotInstalled: until init can move to normal while it
// runs, the box starts normal operation on its next boot.
func (MachineSteps) Handover(context.Context) error {
	return sources.NotInstalled{What: "Moving to normal operation without a restart"}
}
