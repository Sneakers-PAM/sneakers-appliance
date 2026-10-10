// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
)

// The closed shell's mcp command runs osadmin's McpService as the login's
// admin: the same answer as the MCP card, and the same mcp.set audit
// entry, marked as an SSH call.
func TestTheShellsMcpCallsRunTheMcpServiceAsTheAdmin(t *testing.T) {
	b := newBox(t)
	ctx := context.Background()
	bob := b.shell("bob")
	g, err := bob.GetMcp(ctx, connect.NewRequest(&accessv1.GetMcpRequest{}))
	if err != nil || g.Msg.GetMcp().GetState() != "not installed" {
		t.Fatalf("%v %v", g, err)
	}
	_, err = bob.SetMcp(ctx, connect.NewRequest(&accessv1.SetMcpRequest{McpEnabled: true, MachineApiEnabled: true}))
	if err == nil {
		t.Fatal("SetMcp with no product installed went through")
	}
	symbolIn(t, err, connect.CodeOf(err), "NOT_AVAILABLE")
	if e := lastEntry(t, b.log, "mcp.set"); e.Actor != "bob" || e.Detail["surface"] != "ssh" || e.KeyFP != b.keys["bob"].fp || e.Detail["mcp"] != "on" {
		t.Fatalf("%+v", e)
	}
}
