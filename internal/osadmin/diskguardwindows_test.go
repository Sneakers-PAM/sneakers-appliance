// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

// historyLine mirrors osadmin's own (unexported) history record, so a
// test can write upgrade-history.jsonl the way osadmin itself does.
type historyLine struct {
	Time    time.Time `json:"time"`
	Action  string    `json:"action"`
	Version string    `json:"version,omitempty"`
	Actor   string    `json:"actor"`
	Outcome string    `json:"outcome"`
	Detail  string    `json:"detail,omitempty"`
	Target  string    `json:"target,omitempty"`
}

func writeUpgradeHistory(t *testing.T, state string, lines ...historyLine) {
	t.Helper()
	apiDir := filepath.Join(state, "osadmin-api")
	if err := os.MkdirAll(apiDir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(apiDir, "upgrade-history.jsonl")) // #nosec G304 -- a test's own file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, l := range lines {
		b, err := json.Marshal(l)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
	}
}

// The disk guard's growth windows come from the box's own upgrade
// history: a base update and a product reinstall are named, a failed
// apply and a stage that landed nothing are left out.
func TestDiskGuardWindowsFromUpgradeHistory(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	writeUpgradeHistory(t, dir,
		historyLine{Time: now.Add(-2 * time.Hour), Action: "apply", Version: "v0.1.0-rc.2", Actor: "window", Outcome: "ok"},
		historyLine{Time: now.Add(-90 * time.Minute), Action: "reinstall", Version: "v0.1.0-rc.2", Actor: "alice", Outcome: "ok", Target: "product"},
		historyLine{Time: now.Add(-60 * time.Minute), Action: "apply", Version: "v0.1.0-rc.3", Actor: "alice", Outcome: "failed", Target: "product"},
		historyLine{Time: now.Add(-30 * time.Minute), Action: "stage", Version: "v0.1.0-rc.3", Actor: "alice", Outcome: "ok", Target: "product"},
	)
	windows := osadmin.DiskGuardWindows(osadmin.Paths{State: dir})()
	if len(windows) != 2 {
		t.Fatalf("windows %+v", windows)
	}
	if windows[0].Label != "the v0.1.0-rc.2 update" {
		t.Fatalf("the base apply: %+v", windows[0])
	}
	if windows[1].Label != "a product reinstall" {
		t.Fatalf("the product reinstall: %+v", windows[1])
	}
}

// An entry from before diskGuardWindowLookback doesn't come back: it's
// too old to still be excluding one of the guard's own kept samples.
func TestDiskGuardWindowsDropsOldEntries(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	writeUpgradeHistory(t, dir,
		historyLine{Time: now.Add(-30 * 24 * time.Hour), Action: "apply", Version: "v0.0.9", Actor: "window", Outcome: "ok"},
	)
	if windows := osadmin.DiskGuardWindows(osadmin.Paths{State: dir})(); len(windows) != 0 {
		t.Fatalf("an old entry still came back: %+v", windows)
	}
}

// An imported-users marker is a window too, named plainly.
func TestDiskGuardWindowsFromImportMarker(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	if err := os.MkdirAll(filepath.Join(dir, "platform"), 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(map[string]any{"bundle_id": "b1", "job": "job-1", "at": now.Add(-time.Hour), "mode": "rehearsal"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "platform", "imported.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	windows := osadmin.DiskGuardWindows(osadmin.Paths{State: dir})()
	if len(windows) != 1 || windows[0].Label != "an import" {
		t.Fatalf("windows %+v", windows)
	}
}
