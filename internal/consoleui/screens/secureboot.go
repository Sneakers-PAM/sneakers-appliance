// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package screens holds the console's texts and the rules for what an admin
// types at them, free of any terminal code so they test as plain strings.
package screens

import (
	"strings"
)

// Platform is what the box runs on, from the firmware's DMI strings.
type Platform string

// The platforms the enrolment flow tells apart.
const (
	VMware    Platform = "vmware"
	QEMU      Platform = "qemu" // QEMU and Proxmox VE: OVMF starts in Setup Mode
	BareMetal Platform = "bare-metal"
)

// DetectPlatform reads /sys/class/dmi/id/sys_vendor's value.
func DetectPlatform(sysVendor string) Platform {
	v := strings.ToLower(strings.TrimSpace(sysVendor))
	switch {
	case strings.Contains(v, "vmware"):
		return VMware
	case strings.Contains(v, "qemu"):
		return QEMU
	default:
		return BareMetal
	}
}

// TypedNoSecureBoot is what the admin types to run without Secure Boot.
const TypedNoSecureBoot = "no secure boot"

// The reduced-protection warning shown before the admin confirms.
const reducedWarning = "Running without Secure Boot means reduced protection: nothing checks this box's boot files at power-on. The org signature is still checked on every image and every upgrade. Someone with the disk can change this box's software."

// SecureBootChoice is the enrol phase's first screen.
func SecureBootChoice(p Platform) string {
	var b strings.Builder
	b.WriteString("Secure Boot\n\n")
	b.WriteString("  > 1. Use Secure Boot with the org keys (recommended)\n")
	b.WriteString("    2. Run without Secure Boot\n\n")
	b.WriteString("Press Enter to keep 1. To run without Secure Boot, type \"" + TypedNoSecureBoot + "\" and press Enter.\n\n")
	b.WriteString(reducedWarning + "\n")
	if p == VMware {
		b.WriteString("\nOn VMware, if you run without Secure Boot, also remove uefi.allowAuthBypass from the VM's advanced settings.\n")
	}
	return b.String()
}

// Choice reads one line typed at the choice screen: Enter (or "1") keeps
// Secure Boot on; only the exact phrase turns it off. Anything else asks
// again (ok is false).
func Choice(line string) (choice string, ok bool) {
	switch strings.TrimSpace(line) {
	case "", "1":
		return "on", true
	case TypedNoSecureBoot:
		return "off", true
	}
	return "", false
}

// ClearKeys is shown when the admin chose Secure Boot but the firmware isn't
// in Setup Mode: init wrote nothing, and the admin has to delete the PK in
// the firmware first (spec 1 Section 2.5).
func ClearKeys(p Platform) string {
	var b strings.Builder
	b.WriteString("Secure Boot keys can't be enrolled yet: the firmware isn't in Setup Mode. Nothing was written.\n\n")
	switch p {
	case VMware:
		b.WriteString("1. Power the VM off.\n")
		b.WriteString("2. Open the VM's firmware setup: Boot Manager, Enter setup, Secure Boot Configuration, PK Options.\n")
		b.WriteString("3. Delete the PK, and untick \"VMware Default PK\". Save and exit.\n")
		b.WriteString("4. Boot the VM. The org keys are then enrolled by themselves.\n")
	case QEMU:
		b.WriteString("Give the VM an EFI vars store without pre-enrolled keys (Proxmox: pre-enrolled-keys=0), or clear the keys in the firmware setup, then boot again.\n")
	default:
		b.WriteString("Open the firmware setup, clear the Secure Boot keys (this puts the firmware in Setup Mode), save and boot again. The org keys are then enrolled by themselves.\n")
	}
	b.WriteString("\nTo run without Secure Boot instead, type \"" + TypedNoSecureBoot + "\" and press Enter.\n")
	return b.String()
}

// Enrolled is shown after the org keys are written, before the admin turns
// enforcement on.
func Enrolled(p Platform) string {
	switch p {
	case VMware:
		return "Secure Boot keys enrolled. Power the VM off, turn on Secure Boot, remove uefi.allowAuthBypass, power it on.\n"
	case QEMU:
		return "Secure Boot keys enrolled. Restarting with Secure Boot on.\n"
	default:
		return "Secure Boot keys enrolled. Turn on Secure Boot in the firmware setup if it's off, then boot again.\n"
	}
}

// Mismatch is the screen for a box set to Secure Boot whose firmware has it
// off (spec 1 Section 2.7). Nothing starts.
const Mismatch = "Secure Boot is off, but this box is set to use it. Turn it back on in the firmware. To run without it, turn it on, sign in to :8443 and turn Secure Boot off there.\n"
