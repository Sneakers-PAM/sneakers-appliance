// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

package k0s_test

import (
	"testing"
	"time"
)

// The lab hook's phase pods line, as build/lab/overlay/usr/libexec/sneakers/lab-hook
// prints it: each pod ends with ';', with no space before the next.
const hookLine = `lab-hook: phase pods: lab-db restarts=0 started=2026-10-10T19:30:40Z ready=2026-10-10T19:31:25Z;hello restarts=0 started=2026-10-10T19:31:30Z ready=2026-10-10T19:31:41Z;`

func TestThePhasePodsLineReads(t *testing.T) {
	pods, err := readPhasePods(hookLine)
	if err != nil {
		t.Fatal(err)
	}
	db, hello := pods["lab-db"], pods["hello"]
	if len(pods) != 2 || !db.ready.Equal(time.Date(2026, 10, 10, 19, 31, 25, 0, time.UTC)) || !hello.started.Equal(time.Date(2026, 10, 10, 19, 31, 30, 0, time.UTC)) || db.restarts != 0 {
		t.Fatalf("read %+v", pods)
	}
}

func TestSandboxErrorsAreFound(t *testing.T) {
	if got := sandboxErrors(`lab-hook: sandbox events: `); len(got) != 0 {
		t.Fatalf("an empty line has errors: %v", got)
	}
	line := `lab-hook: sandbox events: Failed to create pod sandbox: rpc error: code = Unknown desc = failed to setup network for sandbox "x": plugin type="bridge" failed (add): exec: already started;Failed to create pod sandbox: something else;`
	if got := sandboxErrors(line); len(got) != 1 {
		t.Fatalf("want the one exec: already started event, got %v", got)
	}
}

// After a power loss the phases come up with new pods: a pod that the
// first install started (the same start time) was restarted in place and
// never quiesced.
func TestTheOldPodsAreFound(t *testing.T) {
	before, err := readPhasePods(hookLine)
	if err != nil {
		t.Fatal(err)
	}
	same := `lab-hook: phase pods: lab-db restarts=1 started=2026-10-10T19:30:40Z ready=2026-10-10T19:40:25Z;hello restarts=1 started=2026-10-10T19:31:30Z ready=2026-10-10T19:40:41Z;`
	after, err := readPhasePods(same)
	if err != nil {
		t.Fatal(err)
	}
	if got := oldPods(before, after); len(got) != 2 {
		t.Fatalf("the old pods %v", got)
	}
	fresh := `lab-hook: phase pods: lab-db restarts=0 started=2026-10-10T19:40:10Z ready=2026-10-10T19:41:00Z;hello restarts=0 started=2026-10-10T19:41:02Z ready=2026-10-10T19:41:05Z;`
	if after, err = readPhasePods(fresh); err != nil {
		t.Fatal(err)
	}
	if got := oldPods(before, after); len(got) != 0 {
		t.Fatalf("new pods counted as old: %v", got)
	}
}
