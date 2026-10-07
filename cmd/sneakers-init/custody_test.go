// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody/keycustodytest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/tpm"
)

var ctx = context.Background()

// boot is one boot's custody step over d: a fresh custody, as after a
// reboot, with typed at the console.
func boot(t *testing.T, d *keycustodytest.Disk, sealer keycustody.Sealer, sb secureboot.State, choice phase.SB, typed string) (keycustody.Header, bool, string, error) {
	t.Helper()
	kc := keycustody.New(keycustody.Deps{Disk: d, TPM: sealer, SealedDir: t.TempDir()})
	_, initialized, err := readHeader(ctx, kc)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = openState(ctx, stateDeps{
		custody: kc, hasTPM: sealer != nil, sb: sb, choice: choice,
		in: strings.NewReader(typed), out: &out, logf: t.Logf,
	}, initialized)
	return kc.Header(), initialized, out.String(), err
}

// The first lab target: no Secure Boot firmware, no TPM.
var noSB = secureboot.State{}

func TestNoTPMFirstBootKeepsTheKeyInAKeyFileAndTheNextBootReadsItBack(t *testing.T) {
	d := &keycustodytest.Disk{}
	h, initialized, out, err := boot(t, d, nil, noSB, phase.SBUnset, "\n")
	if err != nil {
		t.Fatal(err)
	}
	if initialized {
		t.Fatal("a new disk counted as set up")
	}
	if h.Mode != keycustody.ModeKeyfile || h.SecureBoot != keycustody.SBOff {
		t.Fatalf("header %+v", h)
	}
	for _, want := range []string{"This box has no TPM", "Protection: reduced (no Secure Boot, no TPM)", "formatted and mounted"} {
		if !strings.Contains(out, want) {
			t.Errorf("the console lacks %q:\n%s", want, out)
		}
	}
	if d.Created[0].Label != "sneakers-keyfile" {
		t.Fatalf("no key-file partition planned: %+v", d.Created)
	}

	h, initialized, out, err = boot(t, d, nil, noSB, phase.SBUnset, "")
	if err != nil {
		t.Fatal(err)
	}
	if !initialized || h.Mode != keycustody.ModeKeyfile || h.SecureBoot != keycustody.SBOff {
		t.Fatalf("after a reboot: initialized=%v header %+v", initialized, h)
	}
	if strings.Contains(out, "At-rest protection\n") {
		t.Fatalf("the reboot asked for the custody again:\n%s", out)
	}
	if !strings.Contains(out, "unlocked and mounted (key file, from the LUKS2 header)") {
		t.Fatalf("the console doesn't say the state is mounted:\n%s", out)
	}
	if !slices.Equal(d.Mounted, []string{"state", "backup", "state", "backup"}) {
		t.Fatalf("mounted %v", d.Mounted)
	}
}

func TestAWipedKeyFileStopsTheBootWithTheReason(t *testing.T) {
	d := &keycustodytest.Disk{}
	if _, _, _, err := boot(t, d, nil, noSB, phase.SBUnset, "\n"); err != nil {
		t.Fatal(err)
	}
	d.WipeKeyfile()
	_, _, out, err := boot(t, d, nil, noSB, phase.SBUnset, "")
	if !codes.Is(err, codes.KeyCustodyLocked) {
		t.Fatalf("want KEYCUSTODY_LOCKED, got %v", err)
	}
	if !strings.Contains(out, "State locked") || !strings.Contains(out, "KEYCUSTODY_LOCKED") || !strings.Contains(out, "Nothing has been started") {
		t.Fatalf("the console doesn't give the reason:\n%s", out)
	}
	if len(d.Mounted) != 2 {
		t.Fatalf("a locked boot mounted something: %v", d.Mounted)
	}
}

func simTPM(t *testing.T) *tpm.TPM {
	t.Helper()
	sim, err := tpm.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sim.Close() })
	if err := sim.ProvisionSRK(); err != nil {
		t.Fatal(err)
	}
	return sim
}

func TestWithATPMEnterKeepsTheTPMAndTheNextBootUnseals(t *testing.T) {
	sim := simTPM(t)
	d := &keycustodytest.Disk{}
	enforcing := secureboot.State{Supported: true, Enforcing: true, OrgOnly: true}
	h, _, out, err := boot(t, d, sim, enforcing, phase.SBUnset, "\n")
	if err != nil {
		t.Fatal(err)
	}
	if h.Mode != keycustody.ModeTPM || h.SecureBoot != keycustody.SBOn {
		t.Fatalf("header %+v", h)
	}
	if !strings.Contains(out, "Use the TPM (recommended)") || !strings.Contains(out, "Protection: full") {
		t.Fatalf("console:\n%s", out)
	}
	if d.Created[0].Label == "sneakers-keyfile" {
		t.Fatal("TPM mode planned a key-file partition")
	}
	if _, _, out, err := boot(t, d, sim, enforcing, phase.SBOn, ""); err != nil || !strings.Contains(out, "(TPM, from the LUKS2 header)") {
		t.Fatalf("the reboot: %v\n%s", err, out)
	}
}

func TestWithATPMTheTypedPhraseChoosesTheKeyFile(t *testing.T) {
	sim := simTPM(t)
	d := &keycustodytest.Disk{}
	h, _, out, err := boot(t, d, sim, noSB, phase.SBUnset, "keyfile\nkey file\n")
	if err != nil {
		t.Fatal(err)
	}
	if h.Mode != keycustody.ModeKeyfile {
		t.Fatalf("header %+v", h)
	}
	if strings.Count(out, "Use the TPM (recommended)") != 2 {
		t.Fatalf("a near miss didn't ask again:\n%s", out)
	}
}

func TestSecureBootOffByChoiceIsRecordedOffEvenWhenEnforcing(t *testing.T) {
	d := &keycustodytest.Disk{}
	h, _, _, err := boot(t, d, nil, secureboot.State{Supported: true, Enforcing: true, OrgOnly: true}, phase.SBOff, "\n")
	if err != nil {
		t.Fatal(err)
	}
	if h.SecureBoot != keycustody.SBOff {
		t.Fatalf("header %+v", h)
	}
}

func TestTheConsoleClosingAtTheProtectionStepInitializesNothing(t *testing.T) {
	d := &keycustodytest.Disk{}
	_, _, _, err := boot(t, d, nil, noSB, phase.SBUnset, "")
	if err == nil || d.Created != nil {
		t.Fatalf("err %v, created %v", err, d.Created)
	}
}
