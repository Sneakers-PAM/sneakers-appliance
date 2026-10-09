// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productswitch"
)

const mcpYAML = `format: 2
switches:
  - name: mcp
    label: The MCP server
    stacks: [sneakers-mcp]
    restart: [sneakers/deployment/sneakers-gateway]
`

// The MCP page's switch is the product's mcp switch: off by default, set
// with a step-up, audited, and kept on the state volume.
func TestTheMCPSwitchTurnsTheProductsMCPStacksOnAndOff(t *testing.T) {
	var restarts []string
	var sw *productswitch.Switches
	b := newBox(t, false, func(b *box, o *osadmin.Options) {
		sw = &productswitch.Switches{Dir: filepath.Join(b.state, "platform"), Slot: filepath.Join(b.state, "product", "current"), Manifests: filepath.Join(b.state, "k0s-manifests"),
			Restart: func(_ context.Context, ns, kind, name string) error {
				restarts = append(restarts, ns+"/"+kind+"/"+name)
				return nil
			}}
		o.Switches = sw
	})
	dir := filepath.Join(b.state, "product")
	installProduct(t, dir, mcpYAML)
	if err := os.MkdirAll(filepath.Join(dir, "a", "manifests", "sneakers-mcp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "manifests", "sneakers-mcp", "mcp.yaml"), []byte("kind: Deployment\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := productspec.WriteRBAC(filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sw.Manifests, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	alice := b.browser()
	alice.signIn("alice")
	mc := osadminv1connect.NewMcpServiceClient(alice.hc, b.ts.URL)
	g, err := mc.GetMcp(ctx, connect.NewRequest(&osadminv1.GetMcpRequest{}))
	if err != nil || g.Msg.GetMcpEnabled() || g.Msg.GetState() != "off" || !g.Msg.GetMachineApiEnabled() {
		t.Fatalf("%v %v", g, err)
	}
	b.clk.Advance(6 * time.Minute)
	_, err = mc.SetMcp(ctx, connect.NewRequest(&osadminv1.SetMcpRequest{McpEnabled: true, MachineApiEnabled: true}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_STEPUP_REQUIRED")
	alice.stepUp("alice")
	if _, err := mc.SetMcp(ctx, connect.NewRequest(&osadminv1.SetMcpRequest{McpEnabled: true, MachineApiEnabled: true})); err != nil {
		t.Fatal(err)
	}
	g, _ = mc.GetMcp(ctx, connect.NewRequest(&osadminv1.GetMcpRequest{}))
	if !g.Msg.GetMcpEnabled() || g.Msg.GetState() != "on" {
		t.Fatalf("%v", g.Msg)
	}
	if _, err := os.Stat(filepath.Join(sw.Manifests, "sneakers-mcp", "mcp.yaml")); err != nil || len(restarts) != 1 {
		t.Fatalf("stack %v restarts %v", err, restarts)
	}
	if e := lastEntry(t, b.log, "mcp.set"); e.Outcome != "ok" || e.Detail["mcp"] != "on" {
		t.Fatalf("audit %+v", e)
	}
	// The product here has no machine-API switch: it stays on.
	_, err = mc.SetMcp(ctx, connect.NewRequest(&osadminv1.SetMcpRequest{McpEnabled: true, MachineApiEnabled: false}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "NOT_AVAILABLE")
}
