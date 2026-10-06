// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package screens

import "github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"

// ProtectionText is the protection line the console, the setup screen and
// Status show (spec 1 Section 2.7), in plain words.
func ProtectionText(p keycustody.Protection, mode keycustody.Mode) string {
	if p.Level == keycustody.LevelFull {
		return "Protection: full. Secure Boot: enforcing, org keys only."
	}
	tail := "Someone with the disk or SD card can change this box's software."
	if mode == keycustody.ModeKeyfile {
		tail = "Someone with the disk or SD card can change this box's software and read its data."
	}
	switch p.Reason {
	case keycustody.ReasonNoSecureBootFirmware:
		if mode == keycustody.ModeKeyfile {
			return "Protection: reduced (no Secure Boot, no TPM). " + tail
		}
		return "Protection: reduced (no Secure Boot). " + tail
	case keycustody.ReasonSecureBootOff:
		return "Protection: reduced (Secure Boot off). " + tail
	case keycustody.ReasonNoTPM:
		return "At-rest protection: reduced (no TPM). Someone with a copy of the whole disk can read its data."
	}
	return "Protection: reduced. " + tail
}
