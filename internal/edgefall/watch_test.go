// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package edgefall_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/edgefall"
)

type source struct {
	p   edgefall.Phase
	err error
}

func (s *source) phase(context.Context) (edgefall.Phase, error) { return s.p, s.err }

func watcher(t *testing.T) (*edgefall.Watcher, *source, string) {
	t.Helper()
	src := &source{err: errors.New("accessd isn't up")}
	file := filepath.Join(t.TempDir(), "box-state")
	return edgefall.NewWatcher(src.phase, file, nil), src, file
}

func poll(t *testing.T, w *edgefall.Watcher, wantState boxstate.State, wantClaim bool) {
	t.Helper()
	w.Poll(context.Background())
	if w.State() != wantState || w.Claim() != wantClaim {
		t.Fatalf("state %q claim %v; want %q %v", w.State(), w.Claim(), wantState, wantClaim)
	}
}

// Before accessd answers, the box is starting and edgefall leaves 443
// alone: k0s may be bringing Traefik up.
func TestBeforeAnAnswerTheBoxIsStartingAndNothingIsClaimed(t *testing.T) {
	w, _, _ := watcher(t)
	poll(t, w, boxstate.Starting, false)
}

// edgefall holds 80 and 443 exactly while the product doesn't run.
func TestTheEdgeIsClaimedWhileTheProductDoesntRun(t *testing.T) {
	w, src, _ := watcher(t)
	src.err = nil
	src.p = edgefall.Phase{ProductInstalled: true, State: "starting"}
	poll(t, w, boxstate.Starting, true)
	src.p = edgefall.Phase{ProductInstalled: true, State: "running", ProductRunning: true}
	poll(t, w, boxstate.Running, false)
	src.p = edgefall.Phase{ProductInstalled: true, State: "updating"}
	poll(t, w, boxstate.Updating, true)
	src.p = edgefall.Phase{ProductInstalled: true, State: "running", ProductRunning: true}
	poll(t, w, boxstate.Running, false)
}

// A reboot holds once seen: accessd stops during the drain, and the page
// keeps saying rebooting, claiming 443 as soon as Traefik lets it go.
func TestARebootHoldsAfterAccessdStops(t *testing.T) {
	w, src, _ := watcher(t)
	src.err = nil
	src.p = edgefall.Phase{ProductInstalled: true, State: "rebooting", ProductRunning: true}
	poll(t, w, boxstate.Rebooting, true)
	src.err = errors.New("accessd drained")
	poll(t, w, boxstate.Rebooting, true)
	src.err = nil
	src.p = edgefall.Phase{ProductInstalled: true, State: "running", ProductRunning: true}
	poll(t, w, boxstate.Rebooting, true)
}

// With accessd already gone, init's announcement still reaches the page.
func TestTheAnnouncementIsReadWhenAccessdIsGone(t *testing.T) {
	w, src, file := watcher(t)
	src.err = nil
	src.p = edgefall.Phase{ProductInstalled: true, State: "running", ProductRunning: true}
	poll(t, w, boxstate.Running, false)
	src.err = errors.New("accessd drained")
	poll(t, w, boxstate.Running, false)
	if err := boxstate.Announce(file, boxstate.ShuttingDown); err != nil {
		t.Fatal(err)
	}
	poll(t, w, boxstate.ShuttingDown, true)
}

// An update's reboot stays an update: the page says why the box went.
func TestAnUpdatesRebootStaysUpdating(t *testing.T) {
	w, src, file := watcher(t)
	src.err = nil
	src.p = edgefall.Phase{ProductInstalled: true, State: "updating", ProductRunning: true}
	poll(t, w, boxstate.Updating, false)
	if err := boxstate.Announce(file, boxstate.Rebooting); err != nil {
		t.Fatal(err)
	}
	src.err = errors.New("accessd drained")
	poll(t, w, boxstate.Updating, true)
}

// accessd restarting on a running box changes nothing: no answer keeps
// the last state.
func TestNoAnswerKeepsTheLastState(t *testing.T) {
	w, src, _ := watcher(t)
	src.err = nil
	src.p = edgefall.Phase{ProductInstalled: true, State: "running", ProductRunning: true}
	poll(t, w, boxstate.Running, false)
	src.err = errors.New("accessd restarting")
	poll(t, w, boxstate.Running, false)
	src.err = nil
	src.p = edgefall.Phase{ProductInstalled: true, State: "nonsense"}
	poll(t, w, boxstate.Running, false)
}

// Before a product bundle is installed nothing answers 80 or 443, through
// a reboot too: nobody has a product page open.
func TestNothingIsClaimedBeforeAProductIsInstalled(t *testing.T) {
	w, src, file := watcher(t)
	src.err = nil
	src.p = edgefall.Phase{State: "starting"}
	poll(t, w, boxstate.Starting, false)
	src.p = edgefall.Phase{State: "rebooting"}
	poll(t, w, boxstate.Rebooting, false)
	src.err = errors.New("accessd drained")
	if err := boxstate.Announce(file, boxstate.Rebooting); err != nil {
		t.Fatal(err)
	}
	poll(t, w, boxstate.Rebooting, false)
}
