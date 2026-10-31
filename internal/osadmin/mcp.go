// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"sync"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
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
	want, applying := s.mcpApply.wanted()
	if applying {
		on = want.mcp
	}
	switch {
	case !ok:
		out.State = "not in this product"
	case on:
		out.McpEnabled, out.State = true, "on"
		out.Readiness, out.Detail = s.mcpReadiness(ctx)
		if applying && out.Readiness == "ready" {
			out.Readiness, out.Detail = "starting", "The switch is still being applied."
		}
	default:
		out.State = "off"
	}
	if api, ok := s.o.Switches.On(spec, switchMachineAPI); ok {
		out.MachineApiEnabled = api
		if applying {
			out.MachineApiEnabled = want.machineAPI
		}
	}
	return connect.NewResponse(out), nil
}

// SetMcp turns the product's MCP (and machine API) on or off. Requests
// collapse to the last one (mcpApply); each is audited on its own.
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
	want := mcpWant{mcp: r.Msg.GetMcpEnabled(), machineAPI: r.Msg.GetMachineApiEnabled()}
	s.o.Logger.Info("osadmin: MCP switch requested", log.F("mcp", want.mcp), log.F("machineApi", want.machineAPI), log.F("by", c.session.Admin))
	select {
	case err := <-s.requestMcp(spec, want):
		if err != nil {
			return nil, err
		}
	case <-ctx.Done():
		return nil, codes.New(codes.ProductNotReady, "MCP is %s; the wait for the product ended", word(want.mcp))
	}
	return connect.NewResponse(&osadminv1.SetMcpResponse{}), nil
}

// mcpWant is the state the MCP page asks for.
type mcpWant struct{ mcp, machineAPI bool }

func (w mcpWant) word() string {
	if w.mcp {
		return "on"
	}
	return "off"
}

// mcpRequest is one SetMcp. done takes its answer, once.
type mcpRequest struct {
	want mcpWant
	spec productspec.Spec
	done chan error
}

// mcpApply runs the MCP switch's changes one at a time. A stack being
// placed or taken away, and the restarts after it, must not run beside
// another's, so requests don't queue up behind each other: only the latest
// waits, and it replaces any that was waiting.
type mcpApply struct {
	mu      sync.Mutex
	working bool
	// running is the request being applied, next the one that waits.
	running, next *mcpRequest
	// applied is what this run of requests last put in place, so a last
	// request that ends where the box already is changes nothing.
	applied *mcpWant
	// stopWait ends running's wait for the product.
	stopWait context.CancelFunc
}

// wanted is the last state asked for, while a request is still being
// applied.
func (a *mcpApply) wanted() (mcpWant, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.next != nil:
		return a.next.want, true
	case a.running != nil:
		return a.running.want, true
	}
	return mcpWant{}, false
}

// requestMcp asks for want and answers on the channel: when it's in place
// and the product is ready with it, or ok at once if a later request
// replaces it first.
func (s *Server) requestMcp(spec productspec.Spec, want mcpWant) <-chan error {
	r := &mcpRequest{want: want, spec: spec, done: make(chan error, 1)}
	a := &s.mcpApply
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.next != nil {
		s.o.Logger.Info("osadmin: a later MCP request replaces the one waiting", log.F("replaced", a.next.want.word()), log.F("mcp", want.word()))
		a.next.done <- nil
	}
	a.next = r
	if a.stopWait != nil {
		a.stopWait()
	}
	if !a.working {
		a.working = true
		go s.runMcp()
	}
	return r.done
}

// runMcp applies the waiting request until none waits. It has its own
// context: a browser that goes away mustn't stop a stack half placed.
func (s *Server) runMcp() {
	a := &s.mcpApply
	for {
		a.mu.Lock()
		r := a.next
		a.next = nil
		if r == nil {
			a.working, a.applied, a.stopWait = false, nil, nil
			a.mu.Unlock()
			return
		}
		a.running = r
		inPlace := a.applied != nil && *a.applied == r.want
		ctx, cancel := context.WithTimeout(context.Background(), mcpApplyBound)
		wait, stopWait := context.WithCancel(ctx)
		a.stopWait = stopWait
		a.mu.Unlock()

		err := s.applyMcp(ctx, wait, r, inPlace)
		stopWait()
		cancel()

		a.mu.Lock()
		a.running, a.stopWait = nil, nil
		a.mu.Unlock()
		r.done <- err
	}
}

// applyMcp puts r in place, unless it's in place already, then waits for
// the product. ctx bounds it, and wait ends the wait for the product.
func (s *Server) applyMcp(ctx, wait context.Context, r *mcpRequest, inPlace bool) error {
	a := &s.mcpApply
	if inPlace {
		s.o.Logger.Info("osadmin: the MCP switch is already where the last request wants it", log.F("mcp", r.want.word()))
	} else {
		if err := s.placeMcp(ctx, r); err != nil {
			a.mu.Lock()
			a.applied = nil
			a.mu.Unlock()
			return err
		}
		a.mu.Lock()
		a.applied = &r.want
		a.mu.Unlock()
	}
	s.o.Logger.Info("osadmin: MCP switch set; waiting for the product to be ready with it", log.F("mcp", r.want.word()), log.F("machineApi", r.want.machineAPI))
	if err := s.waitSwitchReady(wait, r.want.word()); err != nil {
		a.mu.Lock()
		replaced := a.next != nil
		a.mu.Unlock()
		if replaced {
			s.o.Logger.Info("osadmin: a later MCP request ends this one's wait", log.F("mcp", r.want.word()))
			return nil
		}
		if r.want.mcp {
			s.setMcpFailed(err.Error())
		}
		return err
	}
	s.o.Logger.Info("osadmin: the product is ready with the MCP switch", log.F("mcp", r.want.word()))
	return nil
}

// placeMcp sets the switches r asks for.
func (s *Server) placeMcp(ctx context.Context, r *mcpRequest) error {
	if err := s.o.Switches.Set(ctx, r.spec, switchMCP, r.want.mcp); err != nil {
		s.o.Logger.Warn("osadmin: the MCP switch is saved, but putting it in place didn't go through", log.F("mcp", r.want.mcp), log.F("error", err.Error()))
		return switchFailed(r.want.word(), err)
	}
	if _, ok := r.spec.Switch(switchMachineAPI); ok {
		if err := s.o.Switches.Set(ctx, r.spec, switchMachineAPI, r.want.machineAPI); err != nil {
			s.o.Logger.Warn("osadmin: the machine API switch is saved, but putting it in place didn't go through", log.F("machineApi", r.want.machineAPI), log.F("error", err.Error()))
			return switchFailed(mcpWant{mcp: r.want.machineAPI}.word(), err)
		}
	}
	return nil
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

// mcpApplyBound bounds one MCP change: placing its stacks, k0s settling
// them, the restarts and the wait for the product.
const mcpApplyBound = 5 * time.Minute

// DefaultSwitchReadyBound is how long switching MCP waits for the product
// to be ready with it: inside the 2 minutes :8443's front and the closed
// shell wait for an answer.
const DefaultSwitchReadyBound = 90 * time.Second
