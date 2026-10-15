// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/diskguard"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productimport"
)

// diskGuardWindowLookback is how far back the disk guard's growth trend
// ever reads its own retained samples: an event older than this can't
// still be excluding one of them.
const diskGuardWindowLookback = 14 * 24 * time.Hour

// DiskGuardWindows reads paths for the box's own update, revert,
// reinstall, reset and import events, named for the disk guard's growth
// warning (docs/disk-layout.md "Keeping the disk from filling"): it
// never reads one of their one-time steps as a steady rate. It's read
// again at every call, from the upgrade history osadmin already keeps
// (upgrade-history.jsonl) and the imported-users marker (imported.json).
func DiskGuardWindows(paths Paths) func() []diskguard.Window {
	return func() []diskguard.Window {
		since := time.Now().Add(-diskGuardWindowLookback)
		out := upgradeHistoryWindows(paths, since)
		if mk, ok := productimport.ReadMarker(filepath.Join(paths.State, "platform", "imported.json")); ok && mk.At.After(since) {
			out = append(out, diskguard.Window{At: mk.At, Label: "an import"})
		}
		return out
	}
}

// upgradeHistoryWindows is every apply, reinstall, revert or reset that
// landed since since, read from the box's own upgrade history.
func upgradeHistoryWindows(paths Paths, since time.Time) []diskguard.Window {
	f, err := os.Open(filepath.Join(paths.APIDir(), historyFile)) // #nosec G304 -- osadmin's own file
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []diskguard.Window
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e historyEntry
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Outcome != "ok" || e.Time.Before(since) {
			continue
		}
		if label, ok := diskGuardWindowLabel(e); ok {
			out = append(out, diskguard.Window{At: e.Time, Label: label})
		}
	}
	return out
}

// diskGuardWindowLabel names a history entry for the growth message, or
// false for one that doesn't change what a volume holds: a stage, a
// discard, a fetch or a fallback land nothing until an apply, a revert
// or a reset follows.
func diskGuardWindowLabel(e historyEntry) (string, bool) {
	switch e.Action {
	case "apply":
		switch e.Target {
		case "product":
			if e.Version != "" {
				return "the " + e.Version + " product update", true
			}
			return "a product update", true
		case "web":
			return "an admin pages update", true
		default:
			if e.Version != "" {
				return "the " + e.Version + " update", true
			}
			return "an update", true
		}
	case "reinstall":
		return "a product reinstall", true
	case "revert":
		switch e.Target {
		case "product":
			return "a product revert", true
		case "web":
			return "an admin pages revert", true
		default:
			return "a revert", true
		}
	case "reset":
		return "a product reset", true
	}
	return "", false
}
