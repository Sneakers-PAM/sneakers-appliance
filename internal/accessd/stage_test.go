// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/setup"
)

// First boot adds its owner before the owner has a key: the store allows
// that until the admin step is done, and a box without a recovery key
// until the recovery step is.
func TestTheStoreFollowsFirstBootsProgress(t *testing.T) {
	p := setup.Paths{Tmp: t.TempDir(), State: t.TempDir()}
	done := false
	stage := accessd.SetupStage(p, func() bool { return done })
	if a, r := stage(); a || r {
		t.Fatalf("a fresh box: %v %v", a, r)
	}
	m, err := setup.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []setup.Step{setup.StepNetwork, setup.StepProtection, setup.StepAdmin} {
		if err := m.Complete(s); err != nil {
			t.Fatal(err)
		}
	}
	if a, r := stage(); !a || r {
		t.Fatalf("past the admin step: %v %v", a, r)
	}
	done = true
	if a, r := stage(); !a || !r {
		t.Fatalf("set up: %v %v", a, r)
	}
}
