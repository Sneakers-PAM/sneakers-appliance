// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

type mcpAccessd struct {
	fakeAccessd
	state *osadminv1.GetMcpResponse
	sets  []*accessv1.SetMcpRequest
}

func (f *mcpAccessd) GetMcp(_ context.Context, r *connect.Request[accessv1.GetMcpRequest]) (*connect.Response[accessv1.GetMcpResponse], error) {
	f.saw(r.Header())
	return connect.NewResponse(&accessv1.GetMcpResponse{Mcp: f.state}), nil
}

func (f *mcpAccessd) SetMcp(_ context.Context, r *connect.Request[accessv1.SetMcpRequest]) (*connect.Response[accessv1.SetMcpResponse], error) {
	f.saw(r.Header())
	f.sets = append(f.sets, r.Msg)
	f.state.McpEnabled, f.state.MachineApiEnabled = r.Msg.GetMcpEnabled(), r.Msg.GetMachineApiEnabled()
	f.state.State = map[bool]string{true: "on", false: "off"}[r.Msg.GetMcpEnabled()]
	return connect.NewResponse(&accessv1.SetMcpResponse{}), nil
}

func runMcp(t *testing.T, f *mcpAccessd, line string) (string, error) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(accessv1connect.NewAccessServiceHandler(f))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s := &shell.Services{Session: shell.Session{Admin: "alice", KeyFingerprint: "SHA256:abc", Source: "192.0.2.60"}}
	s.UseAccessd(http.DefaultClient, srv.URL)
	var out, errb bytes.Buffer
	e := &shell.Env{Origin: shell.OriginSSH, Backend: s, In: strings.NewReader(""), Out: &out, Err: &errb, Product: sneakers}
	err := shell.Run(context.Background(), e, line)
	return out.String() + errb.String(), err
}

// "<product> mcp" is the same switch as the MCP card on :8443: it shows
// the switch, and on/off set it through accessd, keeping the machine API
// as it is unless the line names it.
func TestTheShellsMcpCommandDrivesTheProductsSwitch(t *testing.T) {
	f := &mcpAccessd{state: &osadminv1.GetMcpResponse{State: "off", MachineApiEnabled: true}}
	out, err := runMcp(t, f, "sneakers mcp")
	if err != nil || !strings.Contains(out, "MCP") || !strings.Contains(out, "off") || !strings.Contains(out, "machine API") {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err = runMcp(t, f, "sneakers mcp on"); err != nil || !strings.Contains(out, "on") {
		t.Fatalf("on: %v\n%s", err, out)
	}
	if len(f.sets) != 1 || !f.sets[0].GetMcpEnabled() || !f.sets[0].GetMachineApiEnabled() {
		t.Fatalf("sets %v", f.sets)
	}
	if _, err = runMcp(t, f, "sneakers mcp off machine-api=off"); err != nil {
		t.Fatal(err)
	}
	if len(f.sets) != 2 || f.sets[1].GetMcpEnabled() || f.sets[1].GetMachineApiEnabled() {
		t.Fatalf("sets %v", f.sets)
	}
	for _, line := range []string{"sneakers mcp maybe", "sneakers mcp on machine-api=perhaps", "sneakers mcp on colour=blue"} {
		_, err := runMcp(t, f, line)
		assertCode(t, err, "SHELL_PARSE")
	}
	if len(f.sets) != 2 {
		t.Fatalf("a bad line set the switch: %v", f.sets)
	}
	f.state = &osadminv1.GetMcpResponse{State: "not in this product", MachineApiEnabled: true}
	if out, err = runMcp(t, f, "sneakers mcp"); err != nil || !strings.Contains(out, "not in this product") {
		t.Fatalf("%v\n%s", err, out)
	}
}
