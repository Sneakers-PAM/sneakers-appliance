// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package phase_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
)

func TestDecidePhase(t *testing.T) {
	cases := []struct {
		name string
		f    phase.Facts
		want phase.Phase
	}{
		{"booted from the ISO", phase.Facts{BootedFromISO: true, SBSupported: true}, phase.Install},
		{"no choice yet", phase.Facts{SBSupported: true, SBChoice: phase.SBUnset}, phase.Enrol},
		{"on, not yet enrolled", phase.Facts{SBSupported: true, SBChoice: phase.SBOn}, phase.Enrol},
		{"on, enforcing with other keys", phase.Facts{SBSupported: true, SBChoice: phase.SBOn, SBEnforcing: true}, phase.Enrol},
		{"off by choice", phase.Facts{SBSupported: true, SBChoice: phase.SBOff}, phase.Firstboot},
		{"no Secure Boot firmware", phase.Facts{SBSupported: false}, phase.Firstboot},
		{"enforcing org-only, set up", phase.Facts{SBSupported: true, SBChoice: phase.SBOn, SBChoiceFixed: true, SBEnforcing: true, SBEnforcingOrgOnly: true, SetupDone: true}, phase.Normal},
		{"no choice, but already enforcing org-only", phase.Facts{SBSupported: true, SBEnforcing: true, SBEnforcingOrgOnly: true}, phase.Firstboot},
		{"enforcing org-only, first boot", phase.Facts{SBSupported: true, SBChoice: phase.SBOn, SBEnforcing: true, SBEnforcingOrgOnly: true}, phase.Firstboot},
		{"off by choice, set up", phase.Facts{SBSupported: true, SBChoice: phase.SBOff, SBChoiceFixed: true, SetupDone: true}, phase.Normal},
		{"mismatch: fixed on, firmware off", phase.Facts{SBSupported: true, SBChoice: phase.SBOn, SBChoiceFixed: true, SetupDone: true}, phase.Mismatch},
		{"mismatch: fixed on, firmware lost its variables", phase.Facts{SBChoice: phase.SBOn, SBChoiceFixed: true, SetupDone: true}, phase.Mismatch},
		{"turned on later: enrol, not mismatch", phase.Facts{SBSupported: true, SBChoice: phase.SBOn, SBChoiceFixed: true, SBEnrolPending: true, SetupDone: true}, phase.Enrol},
		{"a pending factory reset on a set-up box", phase.Facts{SBSupported: true, SBChoice: phase.SBOn, SBChoiceFixed: true, SBEnforcing: true, SBEnforcingOrgOnly: true, SetupDone: true, ResetPending: true}, phase.Reset},
		{"a pending factory reset beats the mismatch screen", phase.Facts{SBSupported: true, SBChoice: phase.SBOn, SBChoiceFixed: true, SetupDone: true, ResetPending: true}, phase.Reset},
		{"turned on later, now enforcing", phase.Facts{SBSupported: true, SBChoice: phase.SBOn, SBChoiceFixed: true, SBEnrolPending: true, SBEnforcing: true, SBEnforcingOrgOnly: true, SetupDone: true}, phase.Normal},
	}
	for _, c := range cases {
		if got := phase.Decide(c.f); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}
