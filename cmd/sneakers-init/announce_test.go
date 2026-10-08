// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"path/filepath"
	"slices"
	"testing"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// A reboot or a shutdown is written to the box-state file, which the
// product edge's box-state page reads, and then put on the screen.
func TestTheAnnouncementGoesToTheBoxStateFileAndTheScreen(t *testing.T) {
	file := filepath.Join(t.TempDir(), "run", "box-state")
	for action, want := range map[string]boxstate.State{osaudit.ActionReboot: boxstate.Rebooting, osaudit.ActionShutdown: boxstate.ShuttingDown} {
		var shown []string
		announce(file, func(a string) { shown = append(shown, a) }, log.Nop())(action)
		if got := boxstate.Read(file); got != want {
			t.Fatalf("%s: the file says %q", action, got)
		}
		if !slices.Equal(shown, []string{action}) {
			t.Fatalf("%s: the screen showed %v", action, shown)
		}
	}
}

// A file that can't be written never stops the reboot's screen.
func TestAnUnwritableBoxStateFileStillShowsTheScreen(t *testing.T) {
	var shown []string
	announce("/proc/no/box-state", func(a string) { shown = append(shown, a) }, log.Nop())(osaudit.ActionReboot)
	if !slices.Equal(shown, []string{osaudit.ActionReboot}) {
		t.Fatalf("the screen showed %v", shown)
	}
}

// The edge fallback stays up through a reboot's or a shutdown's drain.
func TestThePowerDrainKeepsTheEdgeFallback(t *testing.T) {
	if !slices.Equal(drainKeep, []string{"edgefall"}) {
		t.Fatalf("keep %v", drainKeep)
	}
}
