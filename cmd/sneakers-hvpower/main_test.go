// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import "testing"

// qemu-ga runs /sbin/poweroff, /sbin/halt or /sbin/reboot with no
// arguments; the name it ran is the request.
func TestTheNameIsTheRequest(t *testing.T) {
	for name, want := range map[string]action{
		"/sbin/poweroff": powerOff,
		"/sbin/halt":     powerOff,
		"reboot":         reboot,
	} {
		if got, err := actionFor(name); err != nil || got != want {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
	if _, err := actionFor("/usr/libexec/sneakers/sneakers-hvpower"); err == nil {
		t.Fatal("run under its own name it picked an action")
	}
}
