// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
)

// TestSealForImageUnlocksTheNextRelease: a copy sealed to the predicted
// PCR 11 alone (the install copy pruned) still unlocks when PCR 11 holds
// that value.
func TestSealForImageUnlocksTheNextRelease(t *testing.T) {
	needCryptsetup(t)
	sim := simTPM(t)
	d := &fileDisk{dir: t.TempDir()}
	kc := keycustody.New(keycustody.Deps{TPM: sim, Disk: d})
	if err := kc.Initialize(ctx, keycustody.ModeTPM, keycustody.SBOn); err != nil {
		t.Fatal(err)
	}
	if err := sim.ExtendPCR(11, []byte("the running UKI")); err != nil {
		t.Fatal(err)
	}
	pcrs, err := sim.ReadPCRs([]int{11})
	if err != nil {
		t.Fatal(err)
	}
	if err := kc.SealForImage(ctx, "next-uki-sha", pcrs[11]); err != nil {
		t.Fatal(err)
	}
	if err := kc.Prune(ctx, []string{"next-uki-sha"}); err != nil {
		t.Fatal(err)
	}
	if err := keycustody.New(keycustody.Deps{TPM: sim, Disk: d}).Unlock(ctx); err != nil {
		t.Fatalf("the next release's copy must unlock: %v", err)
	}
	if err := kc.Prune(ctx, []string{"nothing"}); !codes.Is(err, codes.KeyCustodyInvalid) {
		t.Fatalf("pruning every copy must be refused: %v", err)
	}
}

func TestSealForImageWithSecureBootOffIsRefused(t *testing.T) {
	needCryptsetup(t)
	sim := simTPM(t)
	kc := keycustody.New(keycustody.Deps{TPM: sim, Disk: &fileDisk{dir: t.TempDir()}})
	if err := kc.Initialize(ctx, keycustody.ModeTPM, keycustody.SBOff); err != nil {
		t.Fatal(err)
	}
	if err := kc.SealForImage(ctx, "x", make([]byte, 32)); !codes.Is(err, codes.UpgradeUnpredictable) {
		t.Fatalf("got %v", err)
	}
}
