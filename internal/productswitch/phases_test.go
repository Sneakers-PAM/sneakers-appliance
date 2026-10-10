// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productswitch_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productswitch"
)

const phasedSpec = spec + `phases:
  - {name: front, label: The gateway, stack: sneakers-front, workloads: [sneakers-gateway, sneakers-mcp], switch_stacks: [sneakers-mcp]}
`

// A switch whose stack a phase places waits for that phase: turned on
// before the product reached it (its phase's own stack isn't in front of
// k0s yet), it's only kept, and the phase loop places it in order; once
// the phase is placed, the switch places its stack at once, as before.
func TestASwitchOfAPhaseWaitsForItsPhase(t *testing.T) {
	b := newBox(t)
	if err := os.WriteFile(filepath.Join(b.slot, productspec.File), []byte(phasedSpec), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := productspec.Load(b.slot)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := b.sw.Set(ctx, s, "mcp", true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.manifests, "sneakers-mcp")); !os.IsNotExist(err) {
		t.Fatalf("the switch placed its stack before its phase: %v", err)
	}
	if len(b.restarts) != 0 {
		t.Fatalf("restarted %v before the phase", b.restarts)
	}
	if on, _ := b.sw.On(s, "mcp"); !on {
		t.Fatal("the setting wasn't kept")
	}
	if err := os.MkdirAll(filepath.Join(b.manifests, "sneakers-front"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := b.sw.Set(ctx, s, "mcp", true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.manifests, "sneakers-mcp", "mcp.yaml")); err != nil {
		t.Fatalf("the phase is placed, and the switch's stack isn't: %v", err)
	}
}

// PlaceStack puts a slot's stack in front of k0s with the box's values,
// as a switch does: the phase loop places each phase's stacks with it.
func TestPlaceStackPutsTheSlotsStackInPlace(t *testing.T) {
	b := newBox(t)
	if err := productswitch.PlaceStack(b.slot, b.platform, b.manifests, "sneakers-mcp"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(b.manifests, "sneakers-mcp", "mcp.yaml"))
	if err != nil || string(got) != "kind: Deployment\n" {
		t.Fatalf("%q %v", got, err)
	}
}
