// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"connectrpc.com/connect"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1/netdv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

// Handler is the NetworkService on its Connect path.
func (d *Daemon) Handler() (string, http.Handler) {
	return netdv1connect.NewNetworkServiceHandler(&handler{d: d})
}

type handler struct {
	netdv1connect.UnimplementedNetworkServiceHandler
	d *Daemon
}

// toConnect maps a coded error to a Connect error whose message starts
// with the code's symbol.
func toConnect(err error) error {
	code, ok := codes.Of(err)
	if !ok {
		return connect.NewError(connect.CodeInternal, err)
	}
	c := connect.CodeFailedPrecondition
	if code == codes.NetInvalid {
		c = connect.CodeInvalidArgument
	}
	return connect.NewError(c, errors.New(codes.Describe(err)))
}

func (h *handler) Get(context.Context, *connect.Request[netdv1.GetRequest]) (*connect.Response[netdv1.GetResponse], error) {
	s, pending := h.d.Get()
	return connect.NewResponse(&netdv1.GetResponse{Settings: network.ToWire(s), Pending: pending}), nil
}

func (h *handler) Set(_ context.Context, r *connect.Request[netdv1.SetRequest]) (*connect.Response[netdv1.SetResponse], error) {
	s, err := network.FromWire(r.Msg.GetSettings())
	if err != nil {
		return nil, toConnect(err)
	}
	tok, err := h.d.Set(s)
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&netdv1.SetResponse{Token: tok, RevertAfterSeconds: int32(network.RevertAfter.Seconds())}), nil
}

func (h *handler) Confirm(_ context.Context, r *connect.Request[netdv1.ConfirmRequest]) (*connect.Response[netdv1.ConfirmResponse], error) {
	if err := h.d.Confirm(r.Msg.GetToken()); err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&netdv1.ConfirmResponse{}), nil
}

var checkStates = map[CheckState]netdv1.CheckState{
	CheckOK: netdv1.CheckState_CHECK_STATE_OK, CheckWarn: netdv1.CheckState_CHECK_STATE_WARN, CheckFailed: netdv1.CheckState_CHECK_STATE_FAILED,
}

func (h *handler) Checks(ctx context.Context, _ *connect.Request[netdv1.ChecksRequest]) (*connect.Response[netdv1.ChecksResponse], error) {
	out := &netdv1.ChecksResponse{}
	for _, c := range h.d.Checks(ctx) {
		out.Checks = append(out.Checks, &netdv1.Check{Name: c.Name, State: checkStates[c.State], Code: c.Code, Detail: c.Detail, Skippable: c.Skippable})
	}
	return connect.NewResponse(out), nil
}

func (h *handler) Status(context.Context, *connect.Request[netdv1.StatusRequest]) (*connect.Response[netdv1.StatusResponse], error) {
	st := h.d.Status()
	return connect.NewResponse(&netdv1.StatusResponse{
		ManagementAddresses: st.Management, ServiceAddresses: st.Service, Hostname: st.Hostname,
		NtpSynced: st.NTPSynced, NtpOffsetMs: st.NTPOffset.Milliseconds(), SshOpen: st.SSHOpen, HttpsOpen: st.HTTPSOpen,
	}), nil
}

func (h *handler) ListInterfaces(context.Context, *connect.Request[netdv1.ListInterfacesRequest]) (*connect.Response[netdv1.ListInterfacesResponse], error) {
	links, err := h.d.Interfaces()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &netdv1.ListInterfacesResponse{}
	for _, l := range links {
		out.Interfaces = append(out.Interfaces, &netdv1.Nic{Name: l.Name, Mac: l.MAC, LinkUp: l.Up, Driver: l.Driver})
	}
	return connect.NewResponse(out), nil
}

func (h *handler) SetManagementPorts(_ context.Context, r *connect.Request[netdv1.SetManagementPortsRequest]) (*connect.Response[netdv1.SetManagementPortsResponse], error) {
	if err := h.d.SetManagementPorts(r.Msg.GetSsh(), r.Msg.GetHttps()); err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&netdv1.SetManagementPortsResponse{}), nil
}

func (h *handler) SetServicePorts(_ context.Context, r *connect.Request[netdv1.SetServicePortsRequest]) (*connect.Response[netdv1.SetServicePortsResponse], error) {
	var rules []PortRule
	for i, w := range r.Msg.GetRules() {
		if w.GetPort() == 0 || w.GetPort() > 65535 {
			return nil, toConnect(codes.Wrap(codes.NetInvalid, &network.FieldError{Field: fmt.Sprintf("rules[%d].port", i), Reason: "give a port from 1 to 65535"}))
		}
		pr := PortRule{Protocol: w.GetProtocol(), Port: uint16(w.GetPort())} // #nosec G115 -- checked above
		for j, a := range w.GetAllow() {
			p, err := netip.ParsePrefix(a)
			if err != nil {
				return nil, toConnect(codes.Wrap(codes.NetInvalid, &network.FieldError{Field: fmt.Sprintf("rules[%d].allow[%d]", i, j), Reason: fmt.Sprintf("%q isn't a prefix", a)}))
			}
			pr.Allow = append(pr.Allow, p.Masked())
		}
		rules = append(rules, pr)
	}
	if err := h.d.SetServicePorts(rules); err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&netdv1.SetServicePortsResponse{}), nil
}

func (h *handler) Watch(ctx context.Context, _ *connect.Request[netdv1.WatchRequest], stream *connect.ServerStream[netdv1.WatchResponse]) error {
	ch, stop := h.d.Watch()
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case a, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(&netdv1.WatchResponse{ManagementAddresses: a.Management, ServiceAddresses: a.Service, Hostname: a.Hostname}); err != nil {
				return err
			}
		}
	}
}
