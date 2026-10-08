// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package weblogin holds the :8443 browser sessions (spec 2, Section 2.6):
// a session starts at a sign-in with a name, a password and a TOTP code,
// and a fresh TOTP code (a step-up) lets it take sensitive actions for 5
// minutes. Everything is kept in memory: a restart signs everyone out.
package weblogin

import (
	"crypto/rand"
	"encoding/base64"
)

// Secret returns 32 random bytes, base64url.
func Secret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
