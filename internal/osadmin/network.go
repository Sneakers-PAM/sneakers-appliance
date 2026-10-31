// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/proto"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netdapi"
	netmodel "github.com/Sneakers-PAM/sneakers-appliance/internal/network"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// adminPort is where the admin pages listen on the management addresses.
const adminPort = "8443"

// revertGrace is how long after a change's window osadmin asks netd how it
// ended, to audit a revert.
const revertGrace = 5 * time.Second

// commitWait bounds a commit: netd's gateway tests take seconds each, and the
// apply is quick.
const commitWait = time.Minute

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
	h.auditRevert(g.Msg.GetLast())
	out := &osadminv1.GetNetworkResponse{
		Settings: g.Msg.GetSettings(), Pending: g.Msg.GetPending(),
		ManagementAddresses: netdapi.Bare(st.Msg.GetManagementAddresses()), ServiceAddresses: st.Msg.GetServiceAddresses(),
		NtpSynced: st.Msg.GetNtpSynced(), NtpOffsetMs: st.Msg.GetNtpOffsetMs(),
		PendingChangeId: g.Msg.GetChangeId(), RevertSecondsLeft: g.Msg.GetSecondsLeft(),
		LearntDns: st.Msg.GetLearntDns(), LearntSearch: st.Msg.GetLearntSearch(), LearntNtp: st.Msg.GetLearntNtp(), NtpServers: st.Msg.GetNtpServers(),
	}
	if l := g.Msg.GetLast(); l.GetReverted() {
		out.LastChangeReverted, out.LastChangeRevertedAtStart, out.LastChangeId = true, l.GetAtStart(), l.GetChangeId()
	}
	if s := g.Msg.GetStaged(); s != nil {
		out.Staged, out.StagedId, out.StagedReview = s, g.Msg.GetStagedId(), review(g.Msg.GetSettings(), s)
	}
	// The token lets the page confirm after a reload or from the change's
	// new address; only an owner may confirm, so only an owner gets it.
	if callFrom(ctx).role == access.RoleOwner {
		out.PendingToken = g.Msg.GetToken()
	}
	return connect.NewResponse(out), nil
}

func (h *networkSvc) SetNetwork(ctx context.Context, r *connect.Request[osadminv1.SetNetworkRequest]) (*connect.Response[osadminv1.SetNetworkResponse], error) {
	c := callFrom(ctx)
	c.note("network")
	// Validate here too, so a refusal names the field before netd is asked.
	if _, err := netmodel.FromWire(r.Msg.GetSettings()); err != nil {
		return nil, err
	}
	prev, err := h.s.o.Network.Get(ctx, connect.NewRequest(&netdv1.GetRequest{}))
	if err != nil {
		return nil, err
	}
	res, err := h.s.o.Network.Set(ctx, connect.NewRequest(&netdv1.SetRequest{Settings: r.Msg.GetSettings()}))
	if err != nil {
		return nil, err
	}
	out := &osadminv1.SetNetworkResponse{Token: res.Msg.GetToken(), RevertAfterSeconds: res.Msg.GetRevertAfterSeconds()}
	out.MovesManagement, out.NewUrl, out.NewCertificate = moves(prev.Msg.GetSettings(), r.Msg.GetSettings())
	if out.GetToken() == "" {
		c.note("network", "kept", "at-once")
		h.s.o.Logger.Info("osadmin: network change kept at once (no address, interface or allow-list change)", log.F("by", c.session.Admin))
		return connect.NewResponse(out), nil
	}
	id := res.Msg.GetChangeId()
	c.note("network", "change", id)
	h.s.o.Logger.Info("osadmin: network change applied, waiting for confirmation", log.F("by", c.session.Admin), log.F("change", id),
		log.F("seconds", res.Msg.GetRevertAfterSeconds()), log.F("movesManagement", out.MovesManagement), log.F("newCertificate", out.NewCertificate))
	after := time.Duration(res.Msg.GetRevertAfterSeconds())*time.Second + revertGrace
	h.s.o.Clock.AfterFunc(after, func() { h.checkRevert(id) })
	return connect.NewResponse(out), nil
}

// StageNetwork passes settings to netd to hold for a commit, and says what
// that commit will do.
func (h *networkSvc) StageNetwork(ctx context.Context, r *connect.Request[osadminv1.StageNetworkRequest]) (*connect.Response[osadminv1.StageNetworkResponse], error) {
	c := callFrom(ctx)
	c.note("network")
	if _, err := netmodel.FromWire(r.Msg.GetSettings()); err != nil {
		return nil, err
	}
	cur, err := h.s.o.Network.Get(ctx, connect.NewRequest(&netdv1.GetRequest{}))
	if err != nil {
		return nil, err
	}
	res, err := h.s.o.Network.Stage(ctx, connect.NewRequest(&netdv1.StageRequest{Settings: r.Msg.GetSettings()}))
	if err != nil {
		return nil, err
	}
	id := res.Msg.GetStagedId()
	c.note("network", "staged", id)
	h.s.o.Logger.Info("osadmin: network change staged", log.F("by", c.session.Admin), log.F("staged", id))
	return connect.NewResponse(&osadminv1.StageNetworkResponse{StagedId: id, Review: review(cur.Msg.GetSettings(), r.Msg.GetSettings())}), nil
}

// DiscardStagedNetwork drops what's staged.
func (h *networkSvc) DiscardStagedNetwork(ctx context.Context, _ *connect.Request[osadminv1.DiscardStagedNetworkRequest]) (*connect.Response[osadminv1.DiscardStagedNetworkResponse], error) {
	c := callFrom(ctx)
	c.note("network")
	if _, err := h.s.o.Network.DiscardStaged(ctx, connect.NewRequest(&netdv1.DiscardStagedRequest{})); err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: staged network change dropped", log.F("by", c.session.Admin))
	return connect.NewResponse(&osadminv1.DiscardStagedNetworkResponse{}), nil
}

// CommitNetwork asks netd to test and apply the staged change. It doesn't
// follow its caller's context: the new address drops the session that asked,
// and netd has to finish and the audit has to say how it ended all the same.
func (h *networkSvc) CommitNetwork(ctx context.Context, r *connect.Request[osadminv1.CommitNetworkRequest]) (*connect.Response[osadminv1.CommitNetworkResponse], error) {
	c := callFrom(ctx)
	id := r.Msg.GetStagedId()
	c.note("network", "staged", id)
	g, err := h.s.o.Network.Get(ctx, connect.NewRequest(&netdv1.GetRequest{}))
	if err != nil {
		return nil, err
	}
	rev := review(g.Msg.GetSettings(), g.Msg.GetStaged())
	h.s.o.Logger.Info("osadmin: network commit asked for", log.F("by", c.session.Admin), log.F("staged", id), log.F("movesManagement", rev.GetMovesManagement()))
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), commitWait)
	defer cancel()
	res, err := h.s.o.Network.Commit(cctx, connect.NewRequest(&netdv1.CommitRequest{StagedId: id}))
	if err != nil {
		h.s.o.Logger.Warn("osadmin: network commit refused", log.F("by", c.session.Admin), log.F("staged", id), log.F("error", err.Error()))
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: network change committed and kept", log.F("by", c.session.Admin), log.F("staged", id), log.F("gateways", len(res.Msg.GetTestedGateways())))
	return connect.NewResponse(&osadminv1.CommitNetworkResponse{TestedGateways: res.Msg.GetTestedGateways(), Review: rev}), nil
}

// review says what committing next over prev does.
func review(prev, next *netdv1.Settings) *osadminv1.StagedReview {
	mv, url, cert := moves(prev, next)
	r := &osadminv1.StagedReview{MovesManagement: mv, NewUrl: url, NewCertificate: cert, ChangesAllowList: !slices.Equal(prev.GetAllowList(), next.GetAllowList())}
	if mv {
		r.NewAddress = staticAddress(next.GetManagement())
	}
	return r
}

// staticAddress is i's static address, IPv4 first; empty when DHCP or SLAAC
// gives it.
func staticAddress(i *netdv1.Interface) string {
	for _, a := range []string{i.GetIpv4().GetAddress(), i.GetIpv6().GetAddress()} {
		if p, err := netip.ParsePrefix(a); err == nil {
			return p.Addr().String()
		}
	}
	return ""
}

// moves says whether next changes the management address the browser
// uses (and the admin page's URL at its new static address), and whether
// the box will make a new self-signed certificate for it.
func moves(prev, next *netdv1.Settings) (bool, string, bool) {
	pm, nm := prev.GetManagement(), next.GetManagement()
	addr := pm.GetName() != nm.GetName() || !proto.Equal(pm.GetIpv4(), nm.GetIpv4()) || !proto.Equal(pm.GetIpv6(), nm.GetIpv6())
	url := ""
	if a := staticAddress(nm); addr && a != "" {
		url = "https://" + net.JoinHostPort(a, adminPort) + "/"
	}
	return addr, url, addr || prev.GetHostname() != next.GetHostname()
}

// checkRevert asks netd how change id ended and audits a revert.
func (h *networkSvc) checkRevert(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	g, err := h.s.o.Network.Get(ctx, connect.NewRequest(&netdv1.GetRequest{}))
	if err != nil {
		h.s.o.Logger.Warn("osadmin: can't ask netd how the network change ended", log.F("change", id), log.F("error", err.Error()))
		return
	}
	if l := g.Msg.GetLast(); l.GetChangeId() == id {
		h.auditRevert(l)
	}
}

// auditRevert writes a reverted change to the audit once.
// A change undone at start is netd's own to audit: osadmin may not have
// run inside its window.
func (h *networkSvc) auditRevert(l *netdv1.ChangeOutcome) {
	if !l.GetReverted() || l.GetChangeId() == "" || l.GetAtStart() {
		return
	}
	h.s.revertMu.Lock()
	if h.s.revertAudited == l.GetChangeId() {
		h.s.revertMu.Unlock()
		return
	}
	h.s.revertAudited = l.GetChangeId()
	h.s.revertMu.Unlock()
	h.s.o.Logger.Error(nil, "osadmin: the network change wasn't confirmed and was undone", log.F("change", l.GetChangeId()))
	h.s.write(osaudit.Entry{Actor: "netd", Action: "network.revert", Target: "network", Detail: map[string]string{"change": l.GetChangeId(), "surface": "netd"}},
		codes.New(codes.NetReverted, "the network change wasn't confirmed in time and was undone"))
}

func (h *networkSvc) ConfirmNetwork(ctx context.Context, r *connect.Request[osadminv1.ConfirmNetworkRequest]) (*connect.Response[osadminv1.ConfirmNetworkResponse], error) {
	c := callFrom(ctx)
	c.note("network")
	if g, err := h.s.o.Network.Get(ctx, connect.NewRequest(&netdv1.GetRequest{})); err == nil && g.Msg.GetChangeId() != "" {
		c.note("network", "change", g.Msg.GetChangeId())
	}
	if _, err := h.s.o.Network.Confirm(ctx, connect.NewRequest(&netdv1.ConfirmRequest{Token: r.Msg.GetToken()})); err != nil {
		return nil, err
	}
	// The certificate held for this confirm; no event says it came.
	h.s.lookAtCerts(0)
	return connect.NewResponse(&osadminv1.ConfirmNetworkResponse{}), nil
}

func (h *networkSvc) RunChecks(ctx context.Context, _ *connect.Request[osadminv1.RunChecksRequest]) (*connect.Response[osadminv1.RunChecksResponse], error) {
	res, err := h.s.o.Network.Checks(ctx, connect.NewRequest(&netdv1.ChecksRequest{}))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.RunChecksResponse{Checks: res.Msg.GetChecks()}), nil
}
