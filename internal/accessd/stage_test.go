// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessd"
)

// Setup makes its first admin through the store, so the store allows no
// admin until the first one exists, and no recovery key until setup is
// done.
func TestTheStoreFollowsSetupsProgress(t *testing.T) {
	first, done := false, false
	stage := accessd.SetupStage(func() bool { return first }, func() bool { return done })
	if a, r := stage(); a || r {
		t.Fatalf("a fresh box: %v %v", a, r)
	}
	first = true
	if a, r := stage(); !a || r {
		t.Fatalf("with the first admin: %v %v", a, r)
	}
	done = true
	if a, r := stage(); !a || !r {
		t.Fatalf("set up: %v %v", a, r)
	}
}
