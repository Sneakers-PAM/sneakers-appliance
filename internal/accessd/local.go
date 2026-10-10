// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd

import (
	"context"
	"net/http"
	"net/netip"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

// run carries out an access.v1 call (procedure) as its caller, through
// the :8443 API's handler fn for apiProcedure, whose rule sets the role it
// needs and the audit action.
func run[Req, Resp any](ctx context.Context, s *Server, h http.Header, procedure, apiProcedure string, fn func(context.Context, *connect.Request[Req]) (*connect.Response[Resp], error), req *Req) (*Resp, error) {
	l, err := s.caller(ctx, h, procedure)
	if err != nil {
		return nil, err
	}
	return runAs(ctx, s, l, apiProcedure, fn, req)
}

func runAs[Req, Resp any](ctx context.Context, s *Server, l osadmin.Local, apiProcedure string, fn func(context.Context, *connect.Request[Req]) (*connect.Response[Resp], error), req *Req) (*Resp, error) {
	var out *Resp
	err := s.api.RunLocal(ctx, l, apiProcedure, func(ctx context.Context) error {
		r, err := fn(ctx, connect.NewRequest(req))
		if err == nil {
			out = r.Msg
		}
		return err
	})
	return out, err
}

type accessH struct {
	accessv1connect.UnimplementedAccessServiceHandler
	s *Server
}

func (h *accessH) GetStatus(ctx context.Context, r *connect.Request[accessv1.GetStatusRequest]) (*connect.Response[accessv1.GetStatusResponse], error) {
	st, err := run(ctx, h.s, r.Header(), accessv1connect.AccessServiceGetStatusProcedure, osadminv1connect.StatusServiceGetStatusProcedure, h.s.h.Status.GetStatus, &osadminv1.GetStatusRequest{})
	if err != nil {
		return nil, err
	}
	h.s.saveStatus(st)
	return connect.NewResponse(&accessv1.GetStatusResponse{Status: st}), nil
}

func (h *accessH) ListAdmins(ctx context.Context, r *connect.Request[accessv1.ListAdminsRequest]) (*connect.Response[accessv1.ListAdminsResponse], error) {
	out, err := run(ctx, h.s, r.Header(), accessv1connect.AccessServiceListAdminsProcedure, osadminv1connect.AccessServiceListAdminsProcedure, h.s.h.Access.ListAdmins, &osadminv1.ListAdminsRequest{})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.ListAdminsResponse{Admins: out.GetAdmins()}), nil
}

func (h *accessH) GetExposedValue(ctx context.Context, r *connect.Request[accessv1.GetExposedValueRequest]) (*connect.Response[accessv1.GetExposedValueResponse], error) {
	out, err := run(ctx, h.s, r.Header(), accessv1connect.AccessServiceGetExposedValueProcedure, osadminv1connect.ProductServiceGetExposedValueProcedure, h.s.h.Product.GetExposedValue,
		&osadminv1.GetExposedValueRequest{Name: r.Msg.GetName()})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.GetExposedValueResponse{Value: out}), nil
}

func (h *accessH) GetMcp(ctx context.Context, r *connect.Request[accessv1.GetMcpRequest]) (*connect.Response[accessv1.GetMcpResponse], error) {
	out, err := run(ctx, h.s, r.Header(), accessv1connect.AccessServiceGetMcpProcedure, osadminv1connect.McpServiceGetMcpProcedure, h.s.h.Mcp.GetMcp, &osadminv1.GetMcpRequest{})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.GetMcpResponse{Mcp: out}), nil
}

func (h *accessH) SetMcp(ctx context.Context, r *connect.Request[accessv1.SetMcpRequest]) (*connect.Response[accessv1.SetMcpResponse], error) {
	if _, err := run(ctx, h.s, r.Header(), accessv1connect.AccessServiceSetMcpProcedure, osadminv1connect.McpServiceSetMcpProcedure, h.s.h.Mcp.SetMcp,
		&osadminv1.SetMcpRequest{McpEnabled: r.Msg.GetMcpEnabled(), MachineApiEnabled: r.Msg.GetMachineApiEnabled()}); err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.SetMcpResponse{}), nil
}

func (h *accessH) GetUpdateChannel(ctx context.Context, r *connect.Request[accessv1.GetUpdateChannelRequest]) (*connect.Response[accessv1.GetUpdateChannelResponse], error) {
	out, err := run(ctx, h.s, r.Header(), accessv1connect.AccessServiceGetUpdateChannelProcedure, osadminv1connect.UpgradeServiceGetUpgradesProcedure, h.s.h.Upgrade.GetUpgrades, &osadminv1.GetUpgradesRequest{})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.GetUpdateChannelResponse{Policy: out.GetPolicy(), MirrorStatus: out.GetMirrorStatus()}), nil
}

// SetUpdateChannel sets the channel or the lab repository override and
// keeps the rest of the policy: it's read, then written back with only
// those changed, as the caller.
func (h *accessH) SetUpdateChannel(ctx context.Context, r *connect.Request[accessv1.SetUpdateChannelRequest]) (*connect.Response[accessv1.SetUpdateChannelResponse], error) {
	l, err := h.s.caller(ctx, r.Header(), accessv1connect.AccessServiceSetUpdateChannelProcedure)
	if err != nil {
		return nil, err
	}
	cur, err := runAs(ctx, h.s, l, osadminv1connect.UpgradeServiceGetUpgradesProcedure, h.s.h.Upgrade.GetUpgrades, &osadminv1.GetUpgradesRequest{})
	if err != nil {
		return nil, err
	}
	p := cur.GetPolicy()
	p.ReleaseChannel, p.ReleaseRepo = r.Msg.ReleaseChannel, r.Msg.ReleaseRepo
	if _, err := runAs(ctx, h.s, l, osadminv1connect.UpgradeServiceSetUpgradePolicyProcedure, h.s.h.Upgrade.SetUpgradePolicy, &osadminv1.SetUpgradePolicyRequest{Policy: p}); err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("accessd: update channel set from the shell", log.F("admin", l.Admin), log.F("channel", r.Msg.GetReleaseChannel()), log.F("repo", r.Msg.GetReleaseRepo()))
	return connect.NewResponse(&accessv1.SetUpdateChannelResponse{}), nil
}

func (h *accessH) CleanUpDisk(ctx context.Context, r *connect.Request[accessv1.CleanUpDiskRequest]) (*connect.Response[accessv1.CleanUpDiskResponse], error) {
	out, err := run(ctx, h.s, r.Header(), accessv1connect.AccessServiceCleanUpDiskProcedure, osadminv1connect.StatusServiceCleanUpDiskProcedure, h.s.h.Status.CleanUpDisk, &osadminv1.CleanUpDiskRequest{})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.CleanUpDiskResponse{Cleanup: out.GetCleanup()}), nil
}

func (h *accessH) AddAdmin(ctx context.Context, r *connect.Request[accessv1.AddAdminRequest]) (*connect.Response[accessv1.AddAdminResponse], error) {
	m := r.Msg
	out, err := run(ctx, h.s, r.Header(), accessv1connect.AccessServiceAddAdminProcedure, osadminv1connect.AccessServiceAddAdminProcedure, h.s.h.Access.AddAdmin,
		&osadminv1.AddAdminRequest{Name: m.GetName(), Role: m.GetRole(), RootOperator: m.GetRootOperator()})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.AddAdminResponse{Admin: out.GetAdmin(), Invitation: out.GetInvitation()}), nil
}

func (h *accessH) RemoveAdmin(ctx context.Context, r *connect.Request[accessv1.RemoveAdminRequest]) (*connect.Response[accessv1.RemoveAdminResponse], error) {
	if _, err := run(ctx, h.s, r.Header(), accessv1connect.AccessServiceRemoveAdminProcedure, osadminv1connect.AccessServiceRemoveAdminProcedure, h.s.h.Access.RemoveAdmin,
		&osadminv1.RemoveAdminRequest{Name: r.Msg.GetName()}); err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.RemoveAdminResponse{}), nil
}

// target is the admin a key call is about: the one named, or the caller.
func target(l osadmin.Local, named string) (string, error) {
	if named != "" {
		return named, nil
	}
	if l.Admin == "" {
		return "", refuse(codes.New(codes.AccessName, "name the admin (--admin)"))
	}
	return l.Admin, nil
}

func (h *accessH) ListKeys(ctx context.Context, r *connect.Request[accessv1.ListKeysRequest]) (*connect.Response[accessv1.ListKeysResponse], error) {
	l, err := h.s.caller(ctx, r.Header(), accessv1connect.AccessServiceListKeysProcedure)
	if err != nil {
		return nil, err
	}
	name, err := target(l, r.Msg.GetAdmin())
	if err != nil {
		return nil, err
	}
	if l.Admin != "" && name != l.Admin {
		st := h.s.store.Read()
		if a, ok := st.Admin(l.Admin); !ok || a.Role != access.RoleOwner {
			return nil, refuse(codes.New(codes.AccessForbidden, "an admin sees only their own keys"))
		}
	}
	out, err := runAs(ctx, h.s, l, osadminv1connect.AccessServiceListAdminsProcedure, h.s.h.Access.ListAdmins, &osadminv1.ListAdminsRequest{})
	if err != nil {
		return nil, err
	}
	for _, a := range out.GetAdmins() {
		if a.GetName() == name {
			return connect.NewResponse(&accessv1.ListKeysResponse{Admin: name, Keys: a.GetKeys()}), nil
		}
	}
	return nil, refuse(codes.New(codes.AccessName, "there is no admin named %q", name))
}

func (h *accessH) RemoveKey(ctx context.Context, r *connect.Request[accessv1.RemoveKeyRequest]) (*connect.Response[accessv1.RemoveKeyResponse], error) {
	l, err := h.s.caller(ctx, r.Header(), accessv1connect.AccessServiceRemoveKeyProcedure)
	if err != nil {
		return nil, err
	}
	name, err := target(l, r.Msg.GetAdmin())
	if err != nil {
		return nil, err
	}
	if _, err := runAs(ctx, h.s, l, osadminv1connect.AccessServiceRemoveKeyProcedure, h.s.h.Access.RemoveKey, &osadminv1.RemoveKeyRequest{Admin: name, Fingerprint: r.Msg.GetFingerprint()}); err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.RemoveKeyResponse{}), nil
}

func (h *accessH) AddRecoveryKey(ctx context.Context, r *connect.Request[accessv1.AddRecoveryKeyRequest]) (*connect.Response[accessv1.AddRecoveryKeyResponse], error) {
	out, err := run(ctx, h.s, r.Header(), accessv1connect.AccessServiceAddRecoveryKeyProcedure, osadminv1connect.SetupServiceAddRecoveryKeyProcedure, h.s.h.Setup.AddRecoveryKey,
		&osadminv1.AddRecoveryKeyRequest{PublicKey: r.Msg.GetPublicKey(), Label: r.Msg.GetLabel()})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.AddRecoveryKeyResponse{RecoveryKey: out.GetRecoveryKey()}), nil
}

type networkH struct {
	accessv1connect.UnimplementedNetworkServiceHandler
	s *Server
}

func (h *networkH) GetNetwork(ctx context.Context, r *connect.Request[accessv1.GetNetworkRequest]) (*connect.Response[accessv1.GetNetworkResponse], error) {
	out, err := run(ctx, h.s, r.Header(), accessv1connect.NetworkServiceGetNetworkProcedure, osadminv1connect.NetworkServiceGetNetworkProcedure, h.s.h.Network.GetNetwork, &osadminv1.GetNetworkRequest{})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.GetNetworkResponse{Settings: out.GetSettings(), ManagementAddresses: out.GetManagementAddresses(), NtpSynced: out.GetNtpSynced()}), nil
}

func (h *networkH) SetNetwork(ctx context.Context, r *connect.Request[accessv1.SetNetworkRequest]) (*connect.Response[accessv1.SetNetworkResponse], error) {
	out, err := run(ctx, h.s, r.Header(), accessv1connect.NetworkServiceSetNetworkProcedure, osadminv1connect.NetworkServiceSetNetworkProcedure, h.s.h.Network.SetNetwork, &osadminv1.SetNetworkRequest{Settings: r.Msg.GetSettings()})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.SetNetworkResponse{Token: out.GetToken(), RevertAfterSeconds: out.GetRevertAfterSeconds()}), nil
}

func (h *networkH) ConfirmNetwork(ctx context.Context, r *connect.Request[accessv1.ConfirmNetworkRequest]) (*connect.Response[accessv1.ConfirmNetworkResponse], error) {
	if _, err := run(ctx, h.s, r.Header(), accessv1connect.NetworkServiceConfirmNetworkProcedure, osadminv1connect.NetworkServiceConfirmNetworkProcedure, h.s.h.Network.ConfirmNetwork, &osadminv1.ConfirmNetworkRequest{Token: r.Msg.GetToken()}); err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.ConfirmNetworkResponse{}), nil
}

// ResetAllowList sets the allow-list to the management interface's own
// subnets, with the usual auto-revert: the console's way back in after a
// bad allow-list.
func (h *networkH) ResetAllowList(ctx context.Context, r *connect.Request[accessv1.ResetAllowListRequest]) (*connect.Response[accessv1.ResetAllowListResponse], error) {
	l, err := h.s.caller(ctx, r.Header(), accessv1connect.NetworkServiceResetAllowListProcedure)
	if err != nil {
		return nil, err
	}
	g, err := h.s.o.Network.Get(ctx, connect.NewRequest(&netdv1.GetRequest{}))
	if err != nil {
		return nil, err
	}
	st, err := h.s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
	if err != nil {
		return nil, err
	}
	var allow []string
	for _, a := range st.Msg.GetManagementAddresses() {
		if p, err := netip.ParsePrefix(a); err == nil && !p.Addr().IsLinkLocalUnicast() {
			allow = append(allow, p.Masked().String())
		}
	}
	if len(allow) == 0 {
		return nil, refuse(codes.New(codes.NetNoAddress, "the management interface has no subnet to allow"))
	}
	settings := g.Msg.GetSettings()
	settings.AllowList = allow
	h.s.o.Logger.Info("accessd: allow-list reset to the on-link subnets", log.F("prefixes", len(allow)))
	out, err := runAs(ctx, h.s, l, osadminv1connect.NetworkServiceSetNetworkProcedure, h.s.h.Network.SetNetwork, &osadminv1.SetNetworkRequest{Settings: settings})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.ResetAllowListResponse{Token: out.GetToken(), RevertAfterSeconds: out.GetRevertAfterSeconds()}), nil
}

type setupH struct {
	accessv1connect.UnimplementedSetupServiceHandler
	s *Server
}

func (h *setupH) GetSetup(ctx context.Context, r *connect.Request[accessv1.GetSetupRequest]) (*connect.Response[accessv1.GetSetupResponse], error) {
	out, err := run(ctx, h.s, r.Header(), accessv1connect.SetupServiceGetSetupProcedure, osadminv1connect.SetupServiceGetSetupProcedure, h.s.h.Setup.GetSetup, &osadminv1.GetSetupRequest{})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.GetSetupResponse{Setup: out}), nil
}

func (h *setupH) SetRecoveryKey(ctx context.Context, r *connect.Request[accessv1.SetRecoveryKeyRequest]) (*connect.Response[accessv1.SetRecoveryKeyResponse], error) {
	out, err := run(ctx, h.s, r.Header(), accessv1connect.SetupServiceSetRecoveryKeyProcedure, osadminv1connect.SetupServiceAddRecoveryKeyProcedure, h.s.h.Setup.AddRecoveryKey,
		&osadminv1.AddRecoveryKeyRequest{PublicKey: r.Msg.GetPublicKey(), Label: r.Msg.GetLabel()})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.SetRecoveryKeyResponse{RecoveryKey: out.GetRecoveryKey()}), nil
}

func (h *setupH) AcknowledgeSingleAdmin(ctx context.Context, r *connect.Request[accessv1.AcknowledgeSingleAdminRequest]) (*connect.Response[accessv1.AcknowledgeSingleAdminResponse], error) {
	if _, err := run(ctx, h.s, r.Header(), accessv1connect.SetupServiceAcknowledgeSingleAdminProcedure, osadminv1connect.SetupServiceAcknowledgeSingleAdminProcedure, h.s.h.Setup.AcknowledgeSingleAdmin, &osadminv1.AcknowledgeSingleAdminRequest{}); err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.AcknowledgeSingleAdminResponse{}), nil
}

func (h *setupH) Complete(ctx context.Context, r *connect.Request[accessv1.CompleteRequest]) (*connect.Response[accessv1.CompleteResponse], error) {
	out, err := run(ctx, h.s, r.Header(), accessv1connect.SetupServiceCompleteProcedure, osadminv1connect.SetupServiceFinishProcedure, h.s.h.Setup.Finish, &osadminv1.FinishRequest{})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.CompleteResponse{ProductSetupUrl: out.GetProductSetupUrl()}), nil
}

type bindingH struct {
	accessv1connect.UnimplementedBindingServiceHandler
	s *Server
}

// GetBinding is the host name and the management addresses :8443 binds:
// no prefix lengths, no link-local addresses.
func (h *bindingH) GetBinding(ctx context.Context, _ *connect.Request[accessv1.GetBindingRequest]) (*connect.Response[accessv1.GetBindingResponse], error) {
	st, err := h.s.o.Network.Status(ctx, connect.NewRequest(&netdv1.StatusRequest{}))
	if err != nil {
		h.s.o.Logger.Warn("accessd: netd didn't give the binding", log.F("error", err.Error()))
		return nil, err
	}
	return connect.NewResponse(&accessv1.GetBindingResponse{Hostname: st.Msg.GetHostname(), ManagementAddresses: Bindable(st.Msg.GetManagementAddresses())}), nil
}

// Bindable turns netd's management addresses (with or without a prefix
// length) into the addresses a listener binds, leaving out link-local ones.
func Bindable(mgmt []string) []string {
	var out []string
	for _, m := range mgmt {
		a, err := netip.ParseAddr(m)
		if err != nil {
			p, perr := netip.ParsePrefix(m)
			if perr != nil {
				continue
			}
			a = p.Addr()
		}
		if !a.IsLinkLocalUnicast() {
			out = append(out, a.String())
		}
	}
	return out
}
