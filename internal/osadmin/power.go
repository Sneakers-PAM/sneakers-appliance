// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

type power struct {
	osadminv1connect.UnimplementedPowerServiceHandler
	s *Server
}

func (h *power) GetPower(context.Context, *connect.Request[osadminv1.GetPowerRequest]) (*connect.Response[osadminv1.GetPowerResponse], error) {
	out := &osadminv1.GetPowerResponse{FactoryReset: h.s.FactoryReset()}
	for _, sess := range h.s.sessions.All() {
		out.Sessions = append(out.Sessions, &osadminv1.ActiveSession{Admin: sess.Admin, SourceAddress: sess.Source, SignedIn: timestamppb.New(sess.SignedIn)})
	}
	st := h.s.o.Access.Read()
	switch q := st.EffectiveQuorum(); {
	case len(st.Admins) < 2:
		out.FactoryResetUnavailableReason = "This box has a single admin, so there is no quorum and no factory reset. Delete and re-create, or re-flash, the box instead."
	case !q.Available():
		out.FactoryResetUnavailableReason = "The quorum roster can't reach its threshold. Fix the roster on the Access page."
	default:
		out.FactoryResetAvailable = true
	}
	return connect.NewResponse(out), nil
}

// errNotAvailable carries the sentence the pages show as written.
var errNotAvailable = errors.New(NotAvailable) //nolint:staticcheck // shown to people as a sentence

func notAvailable() error { return connect.NewError(connect.CodeUnimplemented, errNotAvailable) }

// powerMode checks the forced flags: forced needs its second, explicit
// confirmation.
func powerMode(c *call, forced, confirmed bool) (bool, error) {
	mode := "graceful"
	if forced {
		mode = "forced"
	}
	c.note("box", "mode", mode)
	if forced && !confirmed {
		return false, codes.New(codes.PowerForcedConfirm, "a forced reboot or shutdown cuts every session and may lose data in flight; confirm that a second time")
	}
	return forced, nil
}

func (h *power) Reboot(ctx context.Context, r *connect.Request[osadminv1.RebootRequest]) (*connect.Response[osadminv1.RebootResponse], error) {
	c := callFrom(ctx)
	forced, err := powerMode(c, r.Msg.GetForced(), r.Msg.GetForcedConfirmed())
	if err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: reboot requested", log.F("by", c.session.Admin), log.F("forced", forced), log.F("sessions", len(h.s.sessions.All())))
	if _, err := h.s.o.Power.Reboot(ctx, connect.NewRequest(&initv1.RebootRequest{Forced: forced})); err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.RebootResponse{}), nil
}

func (h *power) Shutdown(ctx context.Context, r *connect.Request[osadminv1.ShutdownRequest]) (*connect.Response[osadminv1.ShutdownResponse], error) {
	c := callFrom(ctx)
	forced, err := powerMode(c, r.Msg.GetForced(), r.Msg.GetForcedConfirmed())
	if err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: shutdown requested", log.F("by", c.session.Admin), log.F("forced", forced), log.F("sessions", len(h.s.sessions.All())))
	if _, err := h.s.o.Power.PowerOff(ctx, connect.NewRequest(&initv1.PowerOffRequest{Forced: forced})); err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.ShutdownResponse{}), nil
}

func (h *power) StartFactoryReset(ctx context.Context, r *connect.Request[osadminv1.StartFactoryResetRequest]) (*connect.Response[osadminv1.StartFactoryResetResponse], error) {
	c := callFrom(ctx)
	c.note("box")
	if err := h.s.confirmHostname(ctx, r.Msg.GetConfirmHostname()); err != nil {
		return nil, err
	}
	fr, err := h.s.startReset(c.session.Admin)
	if err != nil {
		return nil, err
	}
	c.note(fr.GetId())
	return connect.NewResponse(&osadminv1.StartFactoryResetResponse{FactoryReset: fr}), nil
}

func (h *power) ApproveFactoryReset(ctx context.Context, r *connect.Request[osadminv1.ApproveFactoryResetRequest]) (*connect.Response[osadminv1.ApproveFactoryResetResponse], error) {
	c := callFrom(ctx)
	c.note(r.Msg.GetId())
	fr, err := h.s.approveReset(r.Msg.GetId(), c.session.Admin)
	if err != nil {
		return nil, err
	}
	c.note(fr.GetId(), "approvals", itoa(len(fr.GetApprovals())), "required", itoa(int(fr.GetRequired())))
	return connect.NewResponse(&osadminv1.ApproveFactoryResetResponse{FactoryReset: fr}), nil
}

func (h *power) CancelFactoryReset(ctx context.Context, r *connect.Request[osadminv1.CancelFactoryResetRequest]) (*connect.Response[osadminv1.CancelFactoryResetResponse], error) {
	callFrom(ctx).note(r.Msg.GetId())
	if err := h.s.cancelReset(r.Msg.GetId()); err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.CancelFactoryResetResponse{}), nil
}
