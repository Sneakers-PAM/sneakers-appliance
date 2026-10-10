// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package boxstate is what the box is doing, as the product edge's
// box-state page shows it (docs/edge-fallback.md). Init announces a reboot
// or a shutdown in File before anything stops; accessd's public GetPhase
// combines that with the update gate and the product's service, and
// sneakers-edgefall serves the answer on 443.
package boxstate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// File is where init announces a reboot or a shutdown. /run is a tmpfs,
// so a boot starts without one.
const File = "/run/sneakers/box-state"

// State is one box state.
type State string

// The states, as GetPhase answers them and the page shows them.
const (
	Running      State = "running"
	Starting     State = "starting"
	Rebooting    State = "rebooting"
	ShuttingDown State = "shutting-down"
	Updating     State = "updating"
	Maintenance  State = "maintenance"
	// Failed is a product that couldn't start: a phase failed or timed out
	// (docs/upgrades.md#the-phases). 443 stays on the box-state page,
	// which names the phase and the reason, until a revert, a re-apply or
	// a reboot.
	Failed State = "failed"
)

// All lists every state.
var All = []State{Running, Starting, Rebooting, ShuttingDown, Updating, Maintenance, Failed}

// Valid is whether s names a state.
func Valid(s string) bool {
	for _, v := range All {
		if string(v) == s {
			return true
		}
	}
	return false
}

// Going is whether s says the box is going down: once seen, it holds until
// the box is gone.
func Going(s State) bool { return s == Rebooting || s == ShuttingDown }

// maxFile bounds what Read takes of the file.
const maxFile = 64

// Announce writes s, a reboot or a shutdown, to path through a tmp file
// and a rename, readable by everyone on the box.
func Announce(path string, s State) error {
	if !Going(s) {
		return fmt.Errorf("boxstate: init announces a reboot or a shutdown only, not %q", s)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- /run/sneakers, searched by every service
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(string(s)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil { // #nosec G302 -- the state is public: the box-state page shows it to anyone
		return err
	}
	return os.Rename(tmp, path)
}

// Read is the announcement in path, or "" when there is none (no file,
// or anything but a reboot or a shutdown in it).
func Read(path string) State {
	f, err := os.Open(path) // #nosec G304 -- the fixed announcement file
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, maxFile)
	n, _ := f.Read(b)
	s := State(strings.TrimSpace(string(b[:n])))
	if !Going(s) {
		return ""
	}
	return s
}
