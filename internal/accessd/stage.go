// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd

import (
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
)

// SetupStage is the access store's stage: an owner who can sign in is
// required once the first admin exists, a recovery key once setup is done.
// firstAdmin and done read :8443's setup markers.
func SetupStage(firstAdmin, done func() bool) access.Stage {
	return func() (bool, bool) {
		if done() {
			return true, true
		}
		return firstAdmin(), false
	}
}
