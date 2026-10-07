// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package wizard

import (
	"context"
	"sync"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
)

// Steps is first boot's progress: which steps are done, and the move to
// normal operation at the end. The first-boot step machine, with its
// progress file, is the real one; DerivedSteps stands in until it's in the
// build.
type Steps interface {
	Done(ctx context.Context, s Step) (bool, error)
	Complete(ctx context.Context, s Step) error
	// Handover moves the box to normal operation without a restart.
	Handover(ctx context.Context) error
}

// DerivedSteps reads the progress from what the box shows: init fixed the
// protection before this wizard ran, an owner with a key means the admin
// step is done, and accessd's setup state has the recovery keys and the
// finish (written by :8443 after the first sign-in). The network step is
// kept in memory only, so after a restart of the wizard it runs again.
// It can't move the box to normal without a restart.
type DerivedSteps struct {
	Access accessv1connect.AccessServiceClient
	Setup  accessv1connect.SetupServiceClient

	mu   sync.Mutex
	done map[Step]bool
}

// Done reports whether s is done.
func (d *DerivedSteps) Done(ctx context.Context, s Step) (bool, error) {
	d.mu.Lock()
	marked := d.done[s]
	d.mu.Unlock()
	switch s {
	case StepNetwork:
		return marked, nil
	case StepProtection:
		return true, nil
	case StepAdmin:
		r, err := d.Access.ListAdmins(ctx, connect.NewRequest(&accessv1.ListAdminsRequest{}))
		if err != nil {
			return false, err
		}
		for _, a := range r.Msg.GetAdmins() {
			if a.GetRole() == osadminv1.Role_ROLE_OWNER && len(a.GetKeys()) > 0 {
				return true, nil
			}
		}
		return false, nil
	case StepRecovery, StepSignIn:
		r, err := d.Setup.GetSetup(ctx, connect.NewRequest(&accessv1.GetSetupRequest{}))
		if err != nil {
			return false, err
		}
		if s == StepRecovery {
			return len(r.Msg.GetSetup().GetRecoveryKeys()) > 0, nil
		}
		return r.Msg.GetSetup().GetDone(), nil
	}
	return false, nil
}

// Complete marks s done.
func (d *DerivedSteps) Complete(_ context.Context, s Step) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.done == nil {
		d.done = map[Step]bool{}
	}
	d.done[s] = true
	return nil
}

// Handover answers NotInstalled: the move to normal comes with the step
// machine.
func (d *DerivedSteps) Handover(context.Context) error {
	return sources.NotInstalled{What: "Moving to normal operation without a restart"}
}
