// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package phase decides, on every boot, which phase init runs (spec 1
// Sections 2.6 and 2.7): install, enrol, firstboot or normal, or the
// mismatch screen that starts nothing.
package phase

// Phase is one boot phase.
type Phase string

// The phases, in boot order, and the mismatch outcome.
const (
	Install   Phase = "install"
	Enrol     Phase = "enrol"
	Firstboot Phase = "firstboot"
	Normal    Phase = "normal"
	// Mismatch: the box is set to use Secure Boot and the firmware has it
	// off. The console shows the mismatch screen and nothing starts.
	Mismatch Phase = "mismatch"
	// Reset: a factory reset was started and isn't finished. Init carries
	// it on and starts nothing; the box never boots normally until it's
	// done.
	Reset Phase = "reset"
)

// SB is the admin's Secure Boot choice.
type SB string

// The choices.
const (
	SBUnset SB = ""
	SBOn    SB = "on"
	SBOff   SB = "off"
)

// Facts are what init reads at boot before deciding.
type Facts struct {
	// BootedFromISO: the root came from the install medium.
	BootedFromISO bool
	// SBSupported: the firmware exposes SecureBoot or SetupMode.
	SBSupported bool
	// SBChoice is the recorded choice: the LUKS2 header's once first boot
	// fixed it, the ESP file's before that.
	SBChoice SB
	// SBChoiceFixed: SBChoice comes from the LUKS2 header.
	SBChoiceFixed bool
	// SBEnrolPending: the choice was turned on later through the :8443
	// setting and the org keys haven't been seen enforcing since.
	SBEnrolPending bool
	// SBEnforcing: SecureBoot reads 1.
	SBEnforcing bool
	// SBEnforcingOrgOnly: enforcing, and PK, KEK and db hold only the
	// pinned org certificates.
	SBEnforcingOrgOnly bool
	// SetupDone: /var/lib/sneakers/setup/done exists.
	SetupDone bool
	// ResetPending: the ESP's reset.json records a factory reset that
	// isn't done.
	ResetPending bool
}

// Decide picks the phase for f.
func Decide(f Facts) Phase {
	if f.BootedFromISO {
		return Install
	}
	if f.ResetPending {
		return Reset
	}
	after := Firstboot
	if f.SetupDone {
		after = Normal
	}
	// A box fixed to Secure Boot on, already past enrolment, whose firmware
	// no longer enforces: only a signed-in owner may move it to reduced
	// protection, so it doesn't start.
	if f.SBChoiceFixed && f.SBChoice == SBOn && !f.SBEnrolPending && !f.SBEnforcing {
		return Mismatch
	}
	if !f.SBSupported {
		return after
	}
	switch {
	case f.SBChoice == SBOff:
		return after
	case f.SBEnforcingOrgOnly:
		// Already enforcing with only the org keys (QEMU's pre-enrolled
		// vars, or a box enrolled before): there's nothing to choose or
		// enrol.
		return after
	default:
		return Enrol
	}
}
