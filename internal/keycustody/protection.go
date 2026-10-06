// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody

import "github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"

// Level is full or reduced protection.
type Level string

// The levels.
const (
	LevelFull    Level = "full"
	LevelReduced Level = "reduced"
)

// Reason says why protection is reduced.
type Reason string

// The reasons, as spec 1 Section 2.6 names them.
const (
	ReasonNoSecureBootFirmware Reason = "no-secure-boot-firmware"
	ReasonSecureBootOff        Reason = "secure-boot-off"
	ReasonNoTPM                Reason = "no-tpm"
)

// Protection is what Protection() reports.
type Protection struct {
	Level  Level
	Reason Reason
}

// Full is full protection.
func Full() Protection { return Protection{Level: LevelFull} }

// Reduced is reduced protection for reason r.
func Reduced(r Reason) Protection { return Protection{Level: LevelReduced, Reason: r} }

// ProtectionFor is the protection a box has: reduced when the firmware has
// no Secure Boot, when it's off (by choice or not enforcing org-only keys),
// or when the key sits in the key file; full otherwise.
func ProtectionFor(sb secureboot.State, choice SB, mode Mode) Protection {
	switch {
	case !sb.Supported:
		return Reduced(ReasonNoSecureBootFirmware)
	case choice != SBOn || !sb.Enforcing || !sb.OrgOnly:
		return Reduced(ReasonSecureBootOff)
	case mode == ModeKeyfile:
		return Reduced(ReasonNoTPM)
	}
	return Full()
}
