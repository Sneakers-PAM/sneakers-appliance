// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd

import (
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/setup"
)

// SetupStage is the access store's stage from first boot's progress: an
// owner with a key is required once the admin step is done, a recovery key
// once the recovery step is, and both once setup is done (a box set up
// before the step machine has only the done marker).
func SetupStage(p setup.Paths, done func() bool) access.Stage {
	return func() (bool, bool) {
		if done() {
			return true, true
		}
		pr := setup.ReadProgress(p)
		return pr.Done(setup.StepAdmin), pr.Done(setup.StepRecovery)
	}
}
