// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package imageupgrade_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/imageupgrade"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

func TestUnstageRemovesTheStagedEntryOnly(t *testing.T) {
	s, dir, _, sealer, _ := stager(t, "0.0.9")
	if _, err := s.Unstage(ctx); !codes.Is(err, codes.UpgradeNotStaged) {
		t.Fatalf("nothing staged: want UPGRADE_NOT_STAGED, got %v", err)
	}
	if _, err := s.Stage(ctx, verify.LocalLayout(dir), "amd64"); err != nil {
		t.Fatal(err)
	}
	v, err := s.Unstage(ctx)
	if err != nil || v != fixtures.Version {
		t.Fatalf("unstage %q %v", v, err)
	}
	names, _ := s.ESP.List(imageupgrade.UKIDir)
	if len(names) != 1 || names[0] != imageupgrade.GoodName("0.0.9") {
		t.Fatalf("the running entry stays alone: %v", names)
	}
	if st, _ := s.Status(); st.Staged != "" || st.Running != "0.0.9" {
		t.Fatalf("status %+v", st)
	}
	if len(sealer.kept) != 2 {
		t.Fatalf("the unstaged UKI's sealed copy is pruned, keeping the install copy and the running UKI's: %v", sealer.kept)
	}
}
