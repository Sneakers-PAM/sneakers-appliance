// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package screens_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
)

func TestProtectionText(t *testing.T) {
	cases := []struct {
		p    keycustody.Protection
		mode keycustody.Mode
		want string
	}{
		{keycustody.Reduced(keycustody.ReasonSecureBootOff), keycustody.ModeKeyfile, "Protection: reduced (Secure Boot off). Someone with the disk or SD card can change this box's software and read its data."},
		{keycustody.Reduced(keycustody.ReasonSecureBootOff), keycustody.ModeTPM, "Protection: reduced (Secure Boot off). Someone with the disk or SD card can change this box's software."},
		{keycustody.Reduced(keycustody.ReasonNoSecureBootFirmware), keycustody.ModeKeyfile, "Protection: reduced (no Secure Boot, no TPM). Someone with the disk or SD card can change this box's software and read its data."},
		{keycustody.Reduced(keycustody.ReasonNoTPM), keycustody.ModeKeyfile, "At-rest protection: reduced (no TPM). Someone with a copy of the whole disk can read its data."},
		{keycustody.Full(), keycustody.ModeTPM, "Protection: full. Secure Boot: enforcing, org keys only."},
	}
	for _, c := range cases {
		if got := screens.ProtectionText(c.p, c.mode); got != c.want {
			t.Errorf("%+v %s:\n got %q\nwant %q", c.p, c.mode, got, c.want)
		}
	}
}
