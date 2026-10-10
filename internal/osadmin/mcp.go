// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"time"

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
func (h *mcpSvc) GetMcp(ctx context.Context, _ *connect.Request[osadminv1.GetMcpRequest]) (*connect.Response[osadminv1.GetMcpResponse], error) {
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
		out.Readiness, out.Detail = s.mcpReadiness(ctx)
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
	s.setMcpFailed("")
	if err := s.o.Switches.Set(ctx, spec, switchMCP, r.Msg.GetMcpEnabled()); err != nil {
		s.o.Logger.Warn("osadmin: the MCP switch is saved, but putting it in place didn't go through", log.F("mcp", r.Msg.GetMcpEnabled()), log.F("error", err.Error()))
		return nil, switchFailed(word(r.Msg.GetMcpEnabled()), err)
	}
	if _, ok := spec.Switch(switchMachineAPI); ok {
		if err := s.o.Switches.Set(ctx, spec, switchMachineAPI, r.Msg.GetMachineApiEnabled()); err != nil {
			s.o.Logger.Warn("osadmin: the machine API switch is saved, but putting it in place didn't go through", log.F("machineApi", r.Msg.GetMachineApiEnabled()), log.F("error", err.Error()))
			return nil, switchFailed(word(r.Msg.GetMachineApiEnabled()), err)
		}
	}
	s.o.Logger.Info("osadmin: MCP switch set; waiting for the product to be ready with it", log.F("mcp", r.Msg.GetMcpEnabled()), log.F("machineApi", r.Msg.GetMachineApiEnabled()), log.F("by", c.session.Admin))
	if err := s.waitSwitchReady(ctx, word(r.Msg.GetMcpEnabled())); err != nil {
		if r.Msg.GetMcpEnabled() {
			s.setMcpFailed(err.Error())
		}
		return nil, err
	}
	s.o.Logger.Info("osadmin: the product is ready with the MCP switch", log.F("mcp", r.Msg.GetMcpEnabled()))
	return connect.NewResponse(&osadminv1.SetMcpResponse{}), nil
}

// switchFailed is a switch whose stacks or restarts didn't go through,
// with why: the workloads that read it may keep the old setting.
func switchFailed(word string, err error) error {
	if _, ok := codes.Of(err); ok {
		return err
	}
	return codes.New(codes.ProductNotReady, "the switch is saved %s, but the product didn't take it: %s", word, err.Error())
}

// waitSwitchReady waits until the product is ready after a switch change:
// every workload in the stacks that are on (the MCP server's when it's on)
// and those the switch restarted have rolled out, and the product's health
// answers. Past the bound it fails with what the product still waits for.
func (s *Server) waitSwitchReady(ctx context.Context, word string) error {
	if s.o.ProductUp == nil {
		return nil
	}
	every := s.o.Upgrade.ProductUpEvery
	if every <= 0 {
		every = DefaultProductUpEvery
	}
	bound := s.o.Upgrade.SwitchReadyBound
	if bound <= 0 {
		bound = DefaultSwitchReadyBound
	}
	since := s.o.Clock.Now()
	for {
		ok, waiting := s.productReady(ctx)
		if ok {
			return nil
		}
		if s.o.Clock.Now().Sub(since) > bound {
			s.o.Logger.Warn("osadmin: the product isn't ready with the MCP switch within the bound", log.F("mcp", word), log.F("waiting", waiting), log.F("bound", bound.String()))
			return codes.New(codes.ProductNotReady, "MCP is %s, but the product isn't ready with it after %s: %s", word, bound, waiting)
		}
		s.o.Logger.Debug("osadmin: waiting for the product with the MCP switch", log.F("mcp", word), log.F("waiting", waiting))
		select {
		case <-ctx.Done():
			return codes.New(codes.ProductNotReady, "MCP is %s; the wait for the product ended: %s", word, waiting)
		case <-time.After(every):
		}
	}
}

// mcpReadiness is how far the product has come up with MCP on: ready,
// starting with what it waits for, or failed with why the last switch-on
// gave up (until the product is ready).
func (s *Server) mcpReadiness(ctx context.Context) (string, string) {
	ctx, cancel := context.WithTimeout(ctx, mcpReadinessTimeout)
	defer cancel()
	ok, waiting := s.productReady(ctx)
	if ok {
		s.setMcpFailed("")
		return "ready", ""
	}
	s.mcpFailed.mu.Lock()
	reason := s.mcpFailed.reason
	s.mcpFailed.mu.Unlock()
	if reason != "" {
		return "failed", reason
	}
	return "starting", waiting
}

func (s *Server) setMcpFailed(reason string) {
	s.mcpFailed.mu.Lock()
	s.mcpFailed.reason = reason
	s.mcpFailed.mu.Unlock()
}

// mcpReadinessTimeout bounds the MCP page's look at the product.
const mcpReadinessTimeout = 10 * time.Second

// DefaultSwitchReadyBound is how long switching MCP waits for the product
// to be ready with it: inside the 2 minutes :8443's front and the closed
// shell wait for an answer.
const DefaultSwitchReadyBound = 90 * time.Second
