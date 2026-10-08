// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netdapi"
	netmodel "github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

// network passes the page's calls to netd, which validates, applies and
// auto-reverts.
type networkSvc struct {
	osadminv1connect.UnimplementedNetworkServiceHandler
	s *Server
}

func (h *networkSvc) GetNetwork(ctx context.Context, _ *connect.Request[osadminv1.GetNetworkRequest]) (*connect.Response[osadminv1.GetNetworkResponse], error) {
	g, err := h.s.o.Network.Get(ctx, connect.NewRequest(&netdv1.GetRequest{}))
	if err != nil {
		return nil, err
	}
	st, err := h.s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.GetNetworkResponse{
		Settings: g.Msg.GetSettings(), Pending: g.Msg.GetPending(),
		ManagementAddresses: netdapi.Bare(st.Msg.GetManagementAddresses()), ServiceAddresses: st.Msg.GetServiceAddresses(),
		NtpSynced: st.Msg.GetNtpSynced(), NtpOffsetMs: st.Msg.GetNtpOffsetMs(),
	}), nil
}

func (h *networkSvc) SetNetwork(ctx context.Context, r *connect.Request[osadminv1.SetNetworkRequest]) (*connect.Response[osadminv1.SetNetworkResponse], error) {
	c := callFrom(ctx)
	c.note("network")
	// Validate here too, so a refusal names the field before netd is asked.
	if _, err := netmodel.FromWire(r.Msg.GetSettings()); err != nil {
		return nil, err
	}
	res, err := h.s.o.Network.Set(ctx, connect.NewRequest(&netdv1.SetRequest{Settings: r.Msg.GetSettings()}))
	if err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: network change applied, waiting for confirmation", log.F("by", c.session.Admin), log.F("seconds", res.Msg.GetRevertAfterSeconds()))
	return connect.NewResponse(&osadminv1.SetNetworkResponse{Token: res.Msg.GetToken(), RevertAfterSeconds: res.Msg.GetRevertAfterSeconds()}), nil
}

func (h *networkSvc) ConfirmNetwork(ctx context.Context, r *connect.Request[osadminv1.ConfirmNetworkRequest]) (*connect.Response[osadminv1.ConfirmNetworkResponse], error) {
	callFrom(ctx).note("network")
	if _, err := h.s.o.Network.Confirm(ctx, connect.NewRequest(&netdv1.ConfirmRequest{Token: r.Msg.GetToken()})); err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.ConfirmNetworkResponse{}), nil
}

func (h *networkSvc) RunChecks(ctx context.Context, _ *connect.Request[osadminv1.RunChecksRequest]) (*connect.Response[osadminv1.RunChecksResponse], error) {
	res, err := h.s.o.Network.Checks(ctx, connect.NewRequest(&netdv1.ChecksRequest{}))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.RunChecksResponse{Checks: res.Msg.GetChecks()}), nil
}
