// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sshconfig

import (
	"fmt"
	"os"
)

// PrivsepDir is the static sshd's privilege-separation directory (its
// --with-privsep-path) and the sshd account's home. It's on /run, so it's
// made on every boot: sshd, and sshd -t, refuse to run without it.
const PrivsepDir = "/run/sneakers/sshd-empty"

// EnsurePrivsepDir makes dir root's, mode 0755 and empty of rights for
// others, as sshd requires.
func EnsurePrivsepDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- sshd wants its privsep directory 0755 and root's
		return fmt.Errorf("sshconfig: %w", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { // #nosec G302 -- as above
		return fmt.Errorf("sshconfig: %w", err)
	}
	return nil
}
