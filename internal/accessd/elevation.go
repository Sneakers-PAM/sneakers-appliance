// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
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

// RequestElevation is a closed-shell login's: the key it signed in with
// and its SSH client address go into the request. The console has no key
// to sign and can't ask.
func (h *elevationH) RequestElevation(ctx context.Context, r *connect.Request[accessv1.RequestElevationRequest]) (*connect.Response[accessv1.RequestElevationResponse], error) {
	l, err := h.s.caller(ctx, r.Header(), accessv1connect.ElevationServiceRequestElevationProcedure)
	if err != nil {
		return nil, err
	}
	svc, err := h.svc()
	if err != nil {
		return nil, err
	}
	if l.Admin == "" {
		return nil, refuse(codes.New(codes.AccessForbidden, "elevation is asked for from an admin's SSH login, for that login's key"))
	}
	req, err := svc.Request(h.s.store.Read(), elevation.Caller{Admin: l.Admin, KeyFP: l.KeyFP, Source: l.Source}, r.Msg.GetReason(), int(r.Msg.GetMinutes()))
	if err != nil {
		return nil, coded(err)
	}
	return connect.NewResponse(&accessv1.RequestElevationResponse{Elevation: osadmin.ElevationToWire(req, h.auditDir())}), nil
}

func (h *elevationH) ListElevations(ctx context.Context, r *connect.Request[accessv1.ListElevationsRequest]) (*connect.Response[accessv1.ListElevationsResponse], error) {
	out, err := run(ctx, h.s, r.Header(), accessv1connect.ElevationServiceListElevationsProcedure, osadminv1connect.ElevationServiceListElevationsProcedure, h.s.h.Elevation.ListElevations, &osadminv1.ListElevationsRequest{})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.ListElevationsResponse{Elevations: out.GetElevations()}), nil
}

// GetElevationCertificate returns the caller's own approved certificate
// and how to use it.
func (h *elevationH) GetElevationCertificate(ctx context.Context, r *connect.Request[accessv1.GetElevationCertificateRequest]) (*connect.Response[accessv1.GetElevationCertificateResponse], error) {
	l, err := h.s.caller(ctx, r.Header(), accessv1connect.ElevationServiceGetElevationCertificateProcedure)
	if err != nil {
		return nil, err
	}
	svc, err := h.svc()
	if err != nil {
		return nil, err
	}
	req, err := svc.Certificate(l.Admin, r.Msg.GetId())
	if err != nil {
		return nil, coded(err)
	}
	host := "<address>"
	if ns, err := h.s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{})); err == nil {
		if b := Bindable(ns.Msg.GetManagementAddresses()); len(b) > 0 {
			host = b[0]
			if strings.Contains(host, ":") {
				host = "[" + host + "]"
			}
		}
	}
	h.s.o.Logger.Info("accessd: elevation certificate fetched", log.F("id", req.ID), log.F("admin", l.Admin))
	return connect.NewResponse(&accessv1.GetElevationCertificateResponse{
		Certificate: req.Certificate,
		ValidBefore: timestamppb.New(*req.ValidBefore),
		Login:       fmt.Sprintf("Save it beside your key as <key>-cert.pub (for example ~/.ssh/id_ed25519-cert.pub), then within 10 minutes: ssh -i <key> maint@%s", host),
	}), nil
}

func (h *elevationH) ApproveElevation(ctx context.Context, r *connect.Request[accessv1.ApproveElevationRequest]) (*connect.Response[accessv1.ApproveElevationResponse], error) {
	if _, err := run(ctx, h.s, r.Header(), accessv1connect.ElevationServiceApproveElevationProcedure, osadminv1connect.ElevationServiceApproveElevationProcedure, h.s.h.Elevation.ApproveElevation,
		&osadminv1.ApproveElevationRequest{Id: r.Msg.GetId(), Minutes: r.Msg.GetMinutes()}); err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.ApproveElevationResponse{}), nil
}

func (h *elevationH) DenyElevation(ctx context.Context, r *connect.Request[accessv1.DenyElevationRequest]) (*connect.Response[accessv1.DenyElevationResponse], error) {
	if _, err := run(ctx, h.s, r.Header(), accessv1connect.ElevationServiceDenyElevationProcedure, osadminv1connect.ElevationServiceDenyElevationProcedure, h.s.h.Elevation.DenyElevation,
		&osadminv1.DenyElevationRequest{Id: r.Msg.GetId()}); err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.DenyElevationResponse{}), nil
}

func (h *elevationH) TerminateElevation(ctx context.Context, r *connect.Request[accessv1.TerminateElevationRequest]) (*connect.Response[accessv1.TerminateElevationResponse], error) {
	if _, err := run(ctx, h.s, r.Header(), accessv1connect.ElevationServiceTerminateElevationProcedure, osadminv1connect.ElevationServiceTerminateElevationProcedure, h.s.h.Elevation.TerminateElevation,
		&osadminv1.TerminateElevationRequest{Id: r.Msg.GetId()}); err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.TerminateElevationResponse{}), nil
}

// BeginElevatedSession is sneakers-elevated's (root): the certificate is
// used up before it gives a prompt.
func (h *elevationH) BeginElevatedSession(ctx context.Context, r *connect.Request[accessv1.BeginElevatedSessionRequest]) (*connect.Response[accessv1.BeginElevatedSessionResponse], error) {
	if _, err := h.s.caller(ctx, r.Header(), accessv1connect.ElevationServiceBeginElevatedSessionProcedure); err != nil {
		return nil, err
	}
	svc, err := h.svc()
	if err != nil {
		return nil, err
	}
	req, ends, err := svc.Begin(r.Msg.GetCertificate(), int(r.Msg.GetPid()))
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
	case elevation.ReasonExit, elevation.ReasonTimeBox, elevation.ReasonTerminated:
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("the reason is exit, time-box or terminated"))
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
