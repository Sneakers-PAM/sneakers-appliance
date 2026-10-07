// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package screens_test

import (
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
)

func TestCustodyChoice(t *testing.T) {
	for in, want := range map[string]string{"": "tpm", "1": "tpm", "key file": "keyfile", " key file \n": "keyfile"} {
		if got, ok := screens.CustodyChoice(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"2", "keyfile", "Key File", "no tpm"} {
		if _, ok := screens.CustodyChoice(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestCustodyScreens(t *testing.T) {
	sb := "Protection: reduced (Secure Boot off). Someone with the disk or SD card can change this box's software."
	with := screens.CustodyWithTPM(sb)
	for _, want := range []string{sb, "Use the TPM (recommended)", `type "key file"`, "At-rest protection: reduced (no TPM)", ":8443 Status page"} {
		if !strings.Contains(with, want) {
			t.Errorf("the TPM screen lacks %q:\n%s", want, with)
		}
	}
	without := screens.CustodyWithoutTPM(sb)
	for _, want := range []string{sb, "no TPM", "key file", "At-rest protection: reduced (no TPM)", "Press Enter to continue"} {
		if !strings.Contains(without, want) {
			t.Errorf("the no-TPM screen lacks %q:\n%s", want, without)
		}
	}
	if strings.Contains(without, "Use the TPM") {
		t.Error("the no-TPM screen offers the TPM")
	}
	locked := screens.StateLocked("KEYCUSTODY_LOCKED: the key-file partition holds no key")
	for _, want := range []string{"State locked", "KEYCUSTODY_LOCKED: the key-file partition holds no key", "Nothing has been started", "escrow"} {
		if !strings.Contains(locked, want) {
			t.Errorf("the locked screen lacks %q:\n%s", want, locked)
		}
	}
}
