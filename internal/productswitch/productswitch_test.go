// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productswitch_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productswitch"
)

const spec = `format: 2
switches:
  - name: mcp
    label: The MCP server
    stacks: [sneakers-mcp]
    restart: [sneakers/deployment/sneakers-gateway]
`

type box struct {
	slot, platform, manifests string
	restarts                  []string
	sw                        *productswitch.Switches
	spec                      productspec.Spec
}

func newBox(t *testing.T) *box {
	t.Helper()
	d := t.TempDir()
	b := &box{slot: filepath.Join(d, "slot"), platform: filepath.Join(d, "platform"), manifests: filepath.Join(d, "k0s", "manifests")}
	if err := os.MkdirAll(filepath.Join(b.slot, "manifests", "sneakers-mcp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.slot, "manifests", "sneakers-mcp", "mcp.yaml"), []byte("kind: Deployment\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.slot, productspec.File), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := productspec.WriteRBAC(b.slot); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(b.manifests, 0o755); err != nil {
		t.Fatal(err)
	}
	var err error
	b.spec, err = productspec.Load(b.slot)
	if err != nil {
		t.Fatal(err)
	}
	b.sw = &productswitch.Switches{Dir: b.platform, Slot: b.slot, Manifests: b.manifests,
		Restart: func(_ context.Context, ns, kind, name string) error {
			b.restarts = append(b.restarts, ns+"/"+kind+"/"+name)
			return nil
		}}
	return b
}

// A switch is off by default; turning it on puts its stacks in front of
// k0s and restarts what reads them, and off takes them away again. The
// setting lives on the state volume, so it outlives an update and a
// revert, and k0s-interim and the product's progress read the same.
func TestASwitchGatesItsStacks(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	if on, ok := b.sw.On(b.spec, "mcp"); !ok || on {
		t.Fatalf("on %v declared %v", on, ok)
	}
	if off := productswitch.OffStacks(b.slot, b.platform); !slices.Equal(off, []string{"sneakers-mcp"}) {
		t.Fatalf("off %v", off)
	}
	if err := b.sw.Set(ctx, b.spec, "mcp", true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.manifests, "sneakers-mcp", "mcp.yaml")); err != nil {
		t.Fatalf("the stack isn't in front of k0s: %v", err)
	}
	if !slices.Equal(b.restarts, []string{"sneakers/deployment/sneakers-gateway"}) {
		t.Fatalf("restarts %v", b.restarts)
	}
	if off := productswitch.OffStacks(b.slot, b.platform); len(off) != 0 {
		t.Fatalf("off %v", off)
	}
	again := &productswitch.Switches{Dir: b.platform, Slot: b.slot, Manifests: b.manifests}
	if on, _ := again.On(b.spec, "mcp"); !on {
		t.Fatal("the setting didn't outlive a restart")
	}
	if err := b.sw.Set(ctx, b.spec, "mcp", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.manifests, "sneakers-mcp")); !os.IsNotExist(err) {
		t.Fatalf("the stack outlived the switch: %v", err)
	}
	if err := b.sw.Set(ctx, b.spec, "nope", true); err == nil {
		t.Fatal("an undeclared switch was set")
	}
}

// With k0s never started (no manifests directory) the setting is kept and
// k0s-interim applies it at the next start.
func TestASwitchSetWhileK0sIsDownIsKept(t *testing.T) {
	b := newBox(t)
	if err := os.Remove(b.manifests); err != nil {
		t.Fatal(err)
	}
	if err := b.sw.Set(context.Background(), b.spec, "mcp", true); err != nil {
		t.Fatal(err)
	}
	if off := productswitch.OffStacks(b.slot, b.platform); len(off) != 0 {
		t.Fatalf("off %v", off)
	}
}
