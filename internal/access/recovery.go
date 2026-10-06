// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package access

import "time"

// MaxRecoveryKeys is the most recovery keys a box holds.
const MaxRecoveryKeys = 3

// RecoveryKey is a public backup key. Any one of them opens every backup and
// the escrow; the box never holds a private half.
type RecoveryKey struct {
	Key
	Label string    `json:"label,omitempty"`
	Set   time.Time `json:"set"`
	SetBy string    `json:"setBy"`
}
