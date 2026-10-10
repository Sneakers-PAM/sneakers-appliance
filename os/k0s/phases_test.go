// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package k0s_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

func phaseStack(t *testing.T, slot, stack string) bool {
	t.Helper()
	b, err := os.ReadFile("k0s-interim")
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?ms)^phase_stack\(\) \{\n.*?^\}\n`).Find(b)
	if fn == nil {
		t.Fatal("k0s-interim has no phase_stack function")
	}
	script := "set -eu\n" + string(fn) + `if phase_stack "$1" "$2"; then echo phase; else echo always; fi` + "\n"
	out, err := exec.Command("sh", "-c", script, "sh", slot, stack).CombinedOutput() // #nosec G204 -- the repo's own script
	if err != nil {
		t.Fatalf("phase_stack: %v: %s", err, out)
	}
	return string(out) == "phase\n"
}

// k0s-interim leaves a phase's stacks to the box's phase loop, which
// places them one phase at a time once the cluster is up: the slot's
// phase-stacks file (productspec.PhaseStacksFile) names them. Every other
// stack goes in at k0s's start, as before; a slot without phases has no
// such file, and every stack goes in.
func TestK0sInterimLeavesThePhaseStacksToThePhaseLoop(t *testing.T) {
	slot := t.TempDir()
	for st, want := range map[string]bool{"sneakers-data": false, "sneakers": false} {
		if got := phaseStack(t, slot, st); got != want {
			t.Errorf("no phases: %s phase=%v", st, got)
		}
	}
	if err := os.WriteFile(filepath.Join(slot, productspec.PhaseStacksFile), []byte("1 data sneakers-data\n2 front sneakers-mcp\n2 front sneakers-front\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for st, want := range map[string]bool{"sneakers-data": true, "sneakers-mcp": true, "sneakers-front": true, "sneakers": false, "edge": false, "sneakers-dat": false} {
		if got := phaseStack(t, slot, st); got != want {
			t.Errorf("%s phase=%v, want %v", st, got, want)
		}
	}
	b, err := os.ReadFile("k0s-interim")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `if phase_stack "$slot" "$stack"; then`) {
		t.Fatal("prepare doesn't ask phase_stack before it places a stack")
	}
}

// The stacks the phase loop placed are listed in the platform's
// phase-placed file; k0s-interim takes every one of them away at the next
// start, so a revert to a slot without that phase leaves none of it
// behind, and empties the list.
func TestK0sInterimTakesAwayWhatThePhaseLoopPlaced(t *testing.T) {
	b, err := os.ReadFile("k0s-interim")
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?ms)^unplace_phases\(\) \{\n.*?^\}\n`).Find(b)
	if fn == nil {
		t.Fatal("k0s-interim has no unplace_phases function")
	}
	if !strings.Contains(string(b), `unplace_phases /var/lib/sneakers/platform/phase-placed "$data/manifests"`) {
		t.Fatal("prepare doesn't take the placed phase stacks away")
	}
	d := t.TempDir()
	manifests, list := filepath.Join(d, "manifests"), filepath.Join(d, "phase-placed")
	for _, st := range []string{"sneakers-data", "sneakers", "coredns"} {
		if err := os.MkdirAll(filepath.Join(manifests, st), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(list, []byte("sneakers-data\n../coredns\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "set -eu\n" + string(fn) + `unplace_phases "$1" "$2"` + "\n"
	if out, err := exec.Command("sh", "-c", script, "sh", list, manifests).CombinedOutput(); err != nil { // #nosec G204 -- the repo's own script
		t.Fatalf("unplace_phases: %v: %s", err, out)
	}
	for st, want := range map[string]bool{"sneakers-data": false, "sneakers": true, "coredns": true} {
		if _, err := os.Stat(filepath.Join(manifests, st)); (err == nil) != want {
			t.Errorf("%s there=%v, want %v", st, err == nil, want)
		}
	}
	if got, _ := os.ReadFile(list); len(got) != 0 {
		t.Errorf("the list is %q, want empty", got)
	}
}
