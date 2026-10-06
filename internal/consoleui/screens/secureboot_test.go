// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package screens_test

import (
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
)

func TestChoice(t *testing.T) {
	for in, want := range map[string]string{"": "on", "1": "on", "no secure boot": "off", "  no secure boot \n": "off"} {
		if got, ok := screens.Choice(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"2", "no", "No Secure Boot", "off"} {
		if _, ok := screens.Choice(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestScreens(t *testing.T) {
	if !strings.Contains(screens.SecureBootChoice(screens.VMware), "uefi.allowAuthBypass") {
		t.Error("VMware choice screen must mention allowAuthBypass")
	}
	if strings.Contains(screens.SecureBootChoice(screens.QEMU), "allowAuthBypass") {
		t.Error("only VMware mentions allowAuthBypass")
	}
	if !strings.Contains(screens.ClearKeys(screens.VMware), "Delete the PK") || !strings.Contains(screens.ClearKeys(screens.VMware), "no secure boot") {
		t.Error("VMware clear-keys steps")
	}
	want := "Secure Boot is off, but this box is set to use it. Turn it back on in the firmware. To run without it, turn it on, sign in to :8443 and turn Secure Boot off there."
	if !strings.Contains(screens.Mismatch, want) {
		t.Error("mismatch text")
	}
	if screens.DetectPlatform("VMware, Inc.\n") != screens.VMware || screens.DetectPlatform("QEMU") != screens.QEMU || screens.DetectPlatform("Example Corp") != screens.BareMetal {
		t.Error("platform detection")
	}
}
