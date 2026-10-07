// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package elevation_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
)

// sneakers-sshd-run renders the maint principals from elevation.json
// without opening the service: approved requests whose certificate is
// still valid.
func TestReadPrincipalsFromTheStateFile(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	later, earlier := now.Add(5*time.Minute), now.Add(-time.Minute)
	reqs := map[string]any{"requests": []elevation.Request{
		{ID: "E-OPEN", State: elevation.Approved, ValidBefore: &later},
		{ID: "E-LATE", State: elevation.Approved, ValidBefore: &earlier},
		{ID: "E-WAIT", State: elevation.Pending},
	}}
	b, err := json.Marshal(reqs)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "elevation.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := elevation.ReadPrincipals(p, now)
	if err != nil || !slices.Equal(got, []string{"elev-E-OPEN"}) {
		t.Fatalf("principals %v %v", got, err)
	}
	if got, err := elevation.ReadPrincipals(filepath.Join(t.TempDir(), "none.json"), now); err != nil || len(got) != 0 {
		t.Fatalf("no file: %v %v", got, err)
	}
}
