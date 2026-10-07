// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package screens

import "strings"

// TypedKeyFile is what the admin types to keep the state key in a key file
// on a box that has a TPM.
const TypedKeyFile = "key file"

const keyfileWarning = "At-rest protection: reduced (no TPM). Someone who copies this box's disk can read its data."

const changeLater = "The Secure Boot setting can be changed later on the :8443 Status page (an owner, with step-up). The key custody can't: it's fixed until a reinstall.\n"

// CustodyWithTPM is first boot's protection step on a box with a TPM: the
// Secure Boot facts (sbLine), then the custody choice, the TPM by default.
func CustodyWithTPM(sbLine string) string {
	var b strings.Builder
	b.WriteString("At-rest protection\n\n")
	b.WriteString(sbLine + "\n\n")
	b.WriteString("  > 1. Use the TPM (recommended)\n")
	b.WriteString("    2. Key file\n\n")
	b.WriteString("Press Enter to keep 1. To keep the state key in a key file on the disk instead, type \"" + TypedKeyFile + "\" and press Enter.\n")
	b.WriteString("With a key file: " + keyfileWarning + "\n\n")
	b.WriteString(changeLater)
	return b.String()
}

// CustodyWithoutTPM is the protection step on a box without a TPM: the key
// file is the only custody.
func CustodyWithoutTPM(sbLine string) string {
	var b strings.Builder
	b.WriteString("At-rest protection\n\n")
	b.WriteString(sbLine + "\n\n")
	b.WriteString("This box has no TPM, so the state key is kept in a key file on the disk.\n")
	b.WriteString(keyfileWarning + "\n\n")
	b.WriteString(changeLater)
	b.WriteString("\nPress Enter to continue.\n")
	return b.String()
}

// CustodyChoice reads one line typed at CustodyWithTPM: Enter (or "1")
// keeps the TPM; only the exact phrase picks the key file. Anything else
// asks again (ok is false).
func CustodyChoice(line string) (mode string, ok bool) {
	switch strings.TrimSpace(line) {
	case "", "1":
		return "tpm", true
	case TypedKeyFile:
		return "keyfile", true
	}
	return "", false
}

// StateLocked is shown when the state volume doesn't unlock on a box set
// up before. Nothing starts.
func StateLocked(reason string) string {
	var b strings.Builder
	b.WriteString("\nState locked\n\n")
	b.WriteString("The state volume can't be unlocked: " + reason + "\n")
	b.WriteString("Nothing has been started. If the TPM or the key-file partition is gone for good, restore onto a new box from a backup with the escrow bundle.\n")
	return b.String()
}
