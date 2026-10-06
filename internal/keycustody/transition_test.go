// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody_test

import (
	"slices"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/luks"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
)

func pcrSets(t *testing.T, d *fileDisk) [][]int {
	t.Helper()
	s, _, _ := d.volumes()
	toks, err := s.Tokens(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]int
	for _, raw := range toks {
		if tok, err := luks.ParseTPM2Token(raw); err == nil {
			out = append(out, tok.PCRs)
		}
	}
	return out
}

func has(sets [][]int, want []int) bool {
	return slices.ContainsFunc(sets, func(s []int) bool { return slices.Equal(s, want) })
}

var enforcing = secureboot.State{Supported: true, Enforcing: true, OrgOnly: true}

// TestTurnOnLaterReseals: installed with Secure Boot off (PCR 4+11), the
// setting turned on, then the firmware enforcing: the key is resealed to
// PCR 7+11, the PCR 4+11 copy is gone, and the box still unlocks.
func TestTurnOnLaterReseals(t *testing.T) {
	needCryptsetup(t)
	sim := simTPM(t)
	d := &fileDisk{dir: t.TempDir()}
	kc := keycustody.New(keycustody.Deps{TPM: sim, Disk: d})
	if err := kc.Initialize(ctx, keycustody.ModeTPM, keycustody.SBOff); err != nil {
		t.Fatal(err)
	}
	if err := kc.SetSecureBoot(ctx, true); err != nil {
		t.Fatal(err)
	}
	if h := kc.Header(); h.SecureBoot != keycustody.SBOn || !h.EnrolPending {
		t.Fatalf("header %+v", h)
	}
	// A boot before the keys enforce changes nothing.
	if err := kc.OnBoot(ctx, secureboot.State{Supported: true, SetupMode: true}); err != nil {
		t.Fatal(err)
	}
	if !has(pcrSets(t, d), keycustody.PCRs4And11) {
		t.Fatal("the PCR 4+11 copy must stay until the keys enforce")
	}
	if err := kc.OnBoot(ctx, enforcing); err != nil {
		t.Fatal(err)
	}
	sets := pcrSets(t, d)
	if !has(sets, keycustody.PCRs7And11) || has(sets, keycustody.PCRs4And11) {
		t.Fatalf("tokens %v", sets)
	}
	if kc.Header().EnrolPending {
		t.Fatal("enrolment is done")
	}
	if err := keycustody.New(keycustody.Deps{TPM: sim, Disk: d}).Unlock(ctx); err != nil {
		t.Fatalf("the resealed copy must unlock: %v", err)
	}
}

func TestTurnOffAddsAPCR4Copy(t *testing.T) {
	needCryptsetup(t)
	sim := simTPM(t)
	d := &fileDisk{dir: t.TempDir()}
	kc := keycustody.New(keycustody.Deps{TPM: sim, Disk: d})
	if err := kc.Initialize(ctx, keycustody.ModeTPM, keycustody.SBOn); err != nil {
		t.Fatal(err)
	}
	if err := kc.SetSecureBoot(ctx, false); err != nil {
		t.Fatal(err)
	}
	if sets := pcrSets(t, d); !has(sets, keycustody.PCRs4And11) || !has(sets, keycustody.PCRs7And11) {
		t.Fatalf("tokens %v", sets)
	}
	if err := kc.OnBoot(ctx, secureboot.State{Supported: true}); err != nil {
		t.Fatal(err)
	}
	if sets := pcrSets(t, d); has(sets, keycustody.PCRs7And11) || !has(sets, keycustody.PCRs4And11) {
		t.Fatalf("after the off boot: %v", sets)
	}
}

func TestKeyfileModeRecordsTheChoiceOnly(t *testing.T) {
	needCryptsetup(t)
	d := &fileDisk{dir: t.TempDir()}
	kc := keycustody.New(keycustody.Deps{Disk: d})
	if err := kc.Initialize(ctx, keycustody.ModeKeyfile, keycustody.SBOff); err != nil {
		t.Fatal(err)
	}
	if err := kc.SetSecureBoot(ctx, true); err != nil {
		t.Fatal(err)
	}
	h, err := keycustody.New(keycustody.Deps{Disk: d}).Load(ctx)
	if err != nil || h.SecureBoot != keycustody.SBOn || !h.EnrolPending {
		t.Fatalf("%+v %v", h, err)
	}
}
