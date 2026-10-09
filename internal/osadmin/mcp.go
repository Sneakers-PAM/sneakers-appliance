// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// The switches the MCP page drives, as the product's product.yaml names
// them.
const (
	switchMCP        = "mcp"
	switchMachineAPI = "machine-api"
)

type mcpSvc struct {
	osadminv1connect.UnimplementedMcpServiceHandler
	s *Server
}

// GetMcp is the product's mcp switch (and machine-api, when it declares
// one; without it the machine API stays on).
func (h *mcpSvc) GetMcp(context.Context, *connect.Request[osadminv1.GetMcpRequest]) (*connect.Response[osadminv1.GetMcpResponse], error) {
	s := h.s
	out := &osadminv1.GetMcpResponse{MachineApiEnabled: true, State: "not installed"}
	info, spec := s.installedSpec()
	if !info.Present() || s.o.Switches == nil {
		return connect.NewResponse(out), nil
	}
	on, ok := s.o.Switches.On(spec, switchMCP)
	switch {
	case !ok:
		out.State = "not in this product"
	case on:
		out.McpEnabled, out.State = true, "on"
	default:
		out.State = "off"
	}
	if api, ok := s.o.Switches.On(spec, switchMachineAPI); ok {
		out.MachineApiEnabled = api
	}
	return connect.NewResponse(out), nil
}

// SetMcp turns the product's MCP (and machine API) on or off.
func (h *mcpSvc) SetMcp(ctx context.Context, r *connect.Request[osadminv1.SetMcpRequest]) (*connect.Response[osadminv1.SetMcpResponse], error) {
	s, c := h.s, callFrom(ctx)
	word := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	c.note("mcp", "mcp", word(r.Msg.GetMcpEnabled()), "machineApi", word(r.Msg.GetMachineApiEnabled()))
	info, spec := s.installedSpec()
	if !info.Present() || s.o.Switches == nil {
		return nil, codes.New(codes.NotAvailable, "no product is installed")
	}
	if _, ok := spec.Switch(switchMCP); !ok {
		return nil, codes.New(codes.NotAvailable, "%s has no MCP switch", info.Title)
	}
	if _, ok := spec.Switch(switchMachineAPI); !ok && !r.Msg.GetMachineApiEnabled() {
		return nil, codes.New(codes.NotAvailable, "%s has no machine API switch; its machine API stays on", info.Title)
	}
	if err := s.o.Switches.Set(ctx, spec, switchMCP, r.Msg.GetMcpEnabled()); err != nil && !codes.Is(err, codes.NotAvailable) {
		s.o.Logger.Warn("osadmin: the MCP switch is set; a restart after it didn't go through", log.F("error", err.Error()))
	} else if err != nil {
		return nil, err
	}
	if _, ok := spec.Switch(switchMachineAPI); ok {
		if err := s.o.Switches.Set(ctx, spec, switchMachineAPI, r.Msg.GetMachineApiEnabled()); err != nil && codes.Is(err, codes.NotAvailable) {
			return nil, err
		}
	}
	s.o.Logger.Info("osadmin: MCP switch set", log.F("mcp", r.Msg.GetMcpEnabled()), log.F("machineApi", r.Msg.GetMachineApiEnabled()), log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.SetMcpResponse{}), nil
}
