// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tpm

import (
	"testing"
)

// openSim is a test helper that returns a simulator-backed TPM with
// the SRK already provisioned.
func openSim(t *testing.T) *TPM {
	t.Helper()
	tpm, err := OpenSimulator()
	if err != nil {
		t.Fatalf("OpenSimulator: %v", err)
	}
	t.Cleanup(func() {
		if err := tpm.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := tpm.ProvisionSRK(); err != nil {
		t.Fatalf("ProvisionSRK: %v", err)
	}
	return tpm
}

func TestProvisionSRK_Idempotent(t *testing.T) {
	tpm := openSim(t)
	// A second provision must be a no-op and succeed.
	if err := tpm.ProvisionSRK(); err != nil {
		t.Fatalf("second ProvisionSRK: %v", err)
	}
	// And a third, for good measure.
	if err := tpm.ProvisionSRK(); err != nil {
		t.Fatalf("third ProvisionSRK: %v", err)
	}
}
