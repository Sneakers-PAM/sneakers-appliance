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

// RaiseText says how a reduced level can be raised later; empty for full
// protection.
func RaiseText(p keycustody.Protection) string {
	if p.Level == keycustody.LevelFull {
		return ""
	}
	switch p.Reason {
	case keycustody.ReasonSecureBootOff:
		return "To raise it: an owner turns Secure Boot on from the :8443 Status page, then the box enrols the org keys and asks for Secure Boot to be switched on in the firmware. It reseals its key in place: no reinstall, the data stays."
	case keycustody.ReasonNoSecureBootFirmware:
		return "This firmware has no Secure Boot. Protection can be raised only on firmware that has it (on a VM, EFI firmware with Secure Boot): then an owner turns Secure Boot on from the :8443 Status page, with no reinstall."
	case keycustody.ReasonNoTPM:
		return "The state key is in a key file, fixed until a reinstall. To raise it, reinstall on hardware with a TPM (or a VM with a vTPM) and restore from a backup."
	}
	return ""
}
