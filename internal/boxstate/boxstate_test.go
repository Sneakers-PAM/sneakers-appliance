// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxstate_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
)

func TestNoFileIsNoAnnouncement(t *testing.T) {
	if s := boxstate.Read(filepath.Join(t.TempDir(), "box-state")); s != "" {
		t.Fatalf("read %q", s)
	}
}

func TestAnAnnouncementReadsBack(t *testing.T) {
	p := filepath.Join(t.TempDir(), "run", "box-state")
	for _, s := range []boxstate.State{boxstate.Rebooting, boxstate.ShuttingDown} {
		if err := boxstate.Announce(p, s); err != nil {
			t.Fatal(err)
		}
		if got := boxstate.Read(p); got != s {
			t.Fatalf("read %q, want %q", got, s)
		}
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v; everyone on the box may read it", st.Mode().Perm())
	}
}

// Only init's two announcements count: anything else in the file (a
// stray write, a truncated one) is no announcement.
func TestOnlyTheAnnouncedStatesAreRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "box-state")
	for _, body := range []string{"", "running\n", "rebootin", "<html>", "updating\n"} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if s := boxstate.Read(p); s != "" {
			t.Fatalf("%q read as %q", body, s)
		}
	}
	if err := boxstate.Announce(p, boxstate.Updating); err == nil {
		t.Fatal("init announced updating, which accessd owns")
	}
}

func TestTheStatesAreTheOnesThePageKnows(t *testing.T) {
	for _, s := range boxstate.All {
		if !boxstate.Valid(string(s)) {
			t.Fatalf("%q isn't valid", s)
		}
	}
	if boxstate.Valid("down") || boxstate.Valid("") {
		t.Fatal("an unknown state is valid")
	}
}
