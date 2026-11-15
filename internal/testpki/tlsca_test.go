// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package testpki

import (
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
)

// The tests that run on clock.NewFake() (fixed at a date in the past) and the
// ones that run on the real clock take certificates from the same CA, so it
// has to be valid at both times. A window built from time.Now() was valid
// only within 30 days of the fake clock's date, and failed every run after.
func TestTLSCAIsValidOnTheFakeClockAndTheRealOne(t *testing.T) {
	ca := NewTLSCA(t)
	for name, at := range map[string]time.Time{
		"the fake clock": clock.NewFake().Now(),
		"the real clock": time.Now(),
	} {
		for cert, c := range map[string]struct{ from, to time.Time }{
			"root":         {ca.Root.NotBefore, ca.Root.NotAfter},
			"intermediate": {ca.Intermediate.NotBefore, ca.Intermediate.NotAfter},
		} {
			if at.Before(c.from) || at.After(c.to) {
				t.Errorf("the %s is valid from %s to %s, not at %s (%s)", cert, c.from.UTC().Format(time.RFC3339), c.to.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339), name)
			}
		}
	}
}
