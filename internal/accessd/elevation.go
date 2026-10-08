// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

type elevationH struct {
	accessv1connect.UnimplementedElevationServiceHandler
	s *Server
}

var errElevationNotAvailable = connect.NewError(connect.CodeUnimplemented, errors.New(osadmin.NotAvailable)) //nolint:staticcheck // shown to people as a sentence

func (h *elevationH) svc() (*elevation.Service, error) {
	if h.s.o.Elevation == nil {
		return nil, errElevationNotAvailable
	}
	return h.s.o.Elevation, nil
}

func (h *elevationH) auditDir() string { return h.s.o.AuditDir }

// coded turns a refusal from the elevation rules into the Connect error the
// shell reads; anything else passes through.
func coded(err error) error {
	if _, ok := codes.Of(err); ok {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New(codes.Describe(err)))
	}
	return err
}

// BeginRootShell opens a root-shell challenge for a closed-shell login:
// the key it signed in with and its SSH client address are bound to it.
func (h *elevationH) BeginRootShell(ctx context.Context, r *connect.Request[accessv1.BeginRootShellRequest]) (*connect.Response[accessv1.BeginRootShellResponse], error) {
	l, err := h.s.caller(ctx, r.Header(), accessv1connect.ElevationServiceBeginRootShellProcedure)
	if err != nil {
		return nil, err
	}
	if l.Admin == "" {
		return nil, refuse(codes.New(codes.AccessForbidden, "the root shell is opened from an admin's SSH login"))
	}
	req, err := h.s.api.BeginRootShell(l, r.Msg.GetReason())
	if err != nil {
		return nil, coded(err)
	}
	url := ""
	if ns, err := h.s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{})); err == nil {
		if b := Bindable(ns.Msg.GetManagementAddresses()); len(b) > 0 {
			url = "https://" + net.JoinHostPort(b[0], "8443") + "/root-shell"
		}
	}
	return connect.NewResponse(&accessv1.BeginRootShellResponse{Challenge: req.Challenge, Expires: timestamppb.New(*req.ValidBefore), Url: url, Id: req.ID}), nil
}

// OpenRootShell trades a challenge and its code for a ticket to
// rootshell.sock.
func (h *elevationH) OpenRootShell(ctx context.Context, r *connect.Request[accessv1.OpenRootShellRequest]) (*connect.Response[accessv1.OpenRootShellResponse], error) {
	l, err := h.s.caller(ctx, r.Header(), accessv1connect.ElevationServiceOpenRootShellProcedure)
	if err != nil {
		return nil, err
	}
	if l.Admin == "" {
		return nil, refuse(codes.New(codes.AccessForbidden, "the root shell is opened from an admin's SSH login"))
	}
	req, ticket, err := h.s.api.OpenRootShell(l, r.Msg.GetChallenge(), r.Msg.GetCode())
	if err != nil {
		return nil, coded(err)
	}
	return connect.NewResponse(&accessv1.OpenRootShellResponse{Ticket: ticket, SessionMinutes: int32(min(req.Minutes, 1<<30)), Id: req.ID, Socket: h.s.o.Paths.RootShellSocket()}), nil // #nosec G115 -- clamped
}

func (h *elevationH) ListElevations(ctx context.Context, r *connect.Request[accessv1.ListElevationsRequest]) (*connect.Response[accessv1.ListElevationsResponse], error) {
	out, err := run(ctx, h.s, r.Header(), accessv1connect.ElevationServiceListElevationsProcedure, osadminv1connect.ElevationServiceListElevationsProcedure, h.s.h.Elevation.ListElevations, &osadminv1.ListElevationsRequest{})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.ListElevationsResponse{Elevations: out.GetElevations()}), nil
}

func (h *elevationH) TerminateElevation(ctx context.Context, r *connect.Request[accessv1.TerminateElevationRequest]) (*connect.Response[accessv1.TerminateElevationResponse], error) {
	if _, err := run(ctx, h.s, r.Header(), accessv1connect.ElevationServiceTerminateElevationProcedure, osadminv1connect.ElevationServiceTerminateElevationProcedure, h.s.h.Elevation.TerminateElevation,
		&osadminv1.TerminateElevationRequest{Id: r.Msg.GetId()}); err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.TerminateElevationResponse{}), nil
}

// BeginElevatedSession is sneakers-elevated's (root): the ticket is used
// up before it gives a prompt.
func (h *elevationH) BeginElevatedSession(ctx context.Context, r *connect.Request[accessv1.BeginElevatedSessionRequest]) (*connect.Response[accessv1.BeginElevatedSessionResponse], error) {
	if _, err := h.s.caller(ctx, r.Header(), accessv1connect.ElevationServiceBeginElevatedSessionProcedure); err != nil {
		return nil, err
	}
	svc, err := h.svc()
	if err != nil {
		return nil, err
	}
	req, ends, err := svc.Begin(r.Msg.GetTicket(), r.Msg.GetAdmin(), int(r.Msg.GetPid()))
	if err != nil {
		return nil, coded(err)
	}
	return connect.NewResponse(&accessv1.BeginElevatedSessionResponse{Elevation: osadmin.ElevationToWire(req, h.auditDir()), Ends: timestamppb.New(ends)}), nil
}

func (h *elevationH) EndElevatedSession(ctx context.Context, r *connect.Request[accessv1.EndElevatedSessionRequest]) (*connect.Response[accessv1.EndElevatedSessionResponse], error) {
	if _, err := h.s.caller(ctx, r.Header(), accessv1connect.ElevationServiceEndElevatedSessionProcedure); err != nil {
		return nil, err
	}
	svc, err := h.svc()
	if err != nil {
		return nil, err
	}
	switch r.Msg.GetReason() {
	case elevation.ReasonExit, elevation.ReasonIdle, elevation.ReasonTimeBox, elevation.ReasonTerminated:
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the reason is exit, idle, time-box or terminated"))
	}
	if err := svc.End(r.Msg.GetId(), r.Msg.GetReason(), r.Msg.GetRecordingSha256()); err != nil {
		return nil, coded(err)
	}
	return connect.NewResponse(&accessv1.EndElevatedSessionResponse{}), nil
}

// SignalElevated asks a session's sneakers-elevated to end, after checking
// pid is one: a pid can be reused once its process is gone.
func SignalElevated(pid int, signal func(pid int) error) error {
	if pid <= 1 {
		return fmt.Errorf("no session process")
	}
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return fmt.Errorf("the session's process is gone: %w", err)
	}
	if strings.TrimSpace(string(comm)) != "sneakers-elevat" { // comm holds the first 15 bytes of the name
		return fmt.Errorf("pid %d isn't sneakers-elevated", pid)
	}
	return signal(pid)
}
