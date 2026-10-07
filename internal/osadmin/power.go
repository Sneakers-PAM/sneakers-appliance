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
)

type power struct {
	osadminv1connect.UnimplementedPowerServiceHandler
	s *Server
}

func (h *power) GetPower(context.Context, *connect.Request[osadminv1.GetPowerRequest]) (*connect.Response[osadminv1.GetPowerResponse], error) {
	out := &osadminv1.GetPowerResponse{FactoryResetUnavailableReason: NotAvailable}
	for _, sess := range h.s.sessions.All() {
		out.Sessions = append(out.Sessions, &osadminv1.ActiveSession{Admin: sess.Admin, SourceAddress: sess.Source, SignedIn: timestamppb.New(sess.SignedIn)})
	}
	return connect.NewResponse(out), nil
}

// errNotAvailable carries the sentence the pages show as written.
var errNotAvailable = errors.New(NotAvailable) //nolint:staticcheck // shown to people as a sentence

func notAvailable() error { return connect.NewError(connect.CodeUnimplemented, errNotAvailable) }

func (h *power) Reboot(ctx context.Context, r *connect.Request[osadminv1.RebootRequest]) (*connect.Response[osadminv1.RebootResponse], error) {
	c := callFrom(ctx)
	c.note("box", "mode", "graceful")
	if r.Msg.GetForced() {
		return nil, notAvailable()
	}
	h.s.o.Logger.Info("osadmin: reboot requested", log.F("by", c.session.Admin), log.F("sessions", len(h.s.sessions.All())))
	if _, err := h.s.o.Power.Reboot(ctx, connect.NewRequest(&initv1.RebootRequest{})); err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.RebootResponse{}), nil
}

func (h *power) Shutdown(ctx context.Context, r *connect.Request[osadminv1.ShutdownRequest]) (*connect.Response[osadminv1.ShutdownResponse], error) {
	c := callFrom(ctx)
	c.note("box", "mode", "graceful")
	if r.Msg.GetForced() {
		return nil, notAvailable()
	}
	h.s.o.Logger.Info("osadmin: shutdown requested", log.F("by", c.session.Admin), log.F("sessions", len(h.s.sessions.All())))
	if _, err := h.s.o.Power.PowerOff(ctx, connect.NewRequest(&initv1.PowerOffRequest{})); err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.ShutdownResponse{}), nil
}
