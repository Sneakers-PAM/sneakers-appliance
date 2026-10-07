// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package initapi

import (
	"context"
	"net/http"
	"os"
	"strconv"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accounts"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/power"
)

// AccessdPath is where the root image installs sneakers-accessd, which
// runs the :8443 API's backend: its power calls are osadmin's.
// sneakers-osadmin itself runs unprivileged and can't reach init.
const AccessdPath = "/usr/bin/sneakers-accessd"

// The console's programs: the dashboard and the setup wizard. Run by init
// as root, they reboot and power off as the console.
const (
	ConsolePath   = "/usr/bin/sneakers-console"
	FirstbootPath = "/usr/bin/sneakers-firstboot"
)

// DefaultCallers are the programs PowerService answers.
var DefaultCallers = map[string]power.Kind{
	AccessdPath:        power.KindOsadmin,
	accounts.ShellPath: power.KindShell,
	ConsolePath:        power.KindShell,
	FirstbootPath:      power.KindShell,
}

func procExe(pid int32) (string, error) {
	return os.Readlink("/proc/" + strconv.Itoa(int(pid)) + "/exe")
}

func powerHandlerFor(o Options) (string, http.Handler) {
	if o.Power == nil {
		return initv1connect.NewPowerServiceHandler(initv1connect.UnimplementedPowerServiceHandler{})
	}
	return initv1connect.NewPowerServiceHandler(&powerHandler{o: o})
}

type powerHandler struct {
	initv1connect.UnimplementedPowerServiceHandler
	o Options
}

// caller names the peer: its credentials from SO_PEERCRED and the program
// /proc says it runs. Anything not in Callers, or a shell under a uid that
// is neither root (the console) nor an admin, is KindUnknown.
func (h *powerHandler) caller(ctx context.Context) power.Caller {
	p, ok := PeerFrom(ctx)
	if !ok {
		return power.Caller{Kind: power.KindUnknown, Actor: "unknown"}
	}
	c := power.Caller{Kind: power.KindUnknown, UID: p.UID, PID: p.PID}
	exe, err := h.o.ExeOf(p.PID)
	if err != nil {
		c.Actor = "pid " + strconv.Itoa(int(p.PID))
		return c
	}
	c.Actor = exe
	switch h.o.Callers[exe] {
	case power.KindOsadmin:
		c.Kind, c.Actor = power.KindOsadmin, "osadmin"
	case power.KindShell:
		if p.UID == 0 {
			c.Kind, c.Actor = power.KindShell, "console"
		} else if name, ok := h.o.AdminName(p.UID); ok {
			c.Kind, c.Actor = power.KindShell, name
		}
	}
	return c
}

func (h *powerHandler) Reboot(ctx context.Context, r *connect.Request[initv1.RebootRequest]) (*connect.Response[initv1.RebootResponse], error) {
	if err := h.o.Power.Reboot(ctx, h.caller(ctx), r.Msg.GetForced()); err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&initv1.RebootResponse{}), nil
}

func (h *powerHandler) PowerOff(ctx context.Context, r *connect.Request[initv1.PowerOffRequest]) (*connect.Response[initv1.PowerOffResponse], error) {
	if err := h.o.Power.PowerOff(ctx, h.caller(ctx), r.Msg.GetForced()); err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&initv1.PowerOffResponse{}), nil
}

func (h *powerHandler) ArmFactoryReset(ctx context.Context, r *connect.Request[initv1.ArmFactoryResetRequest]) (*connect.Response[initv1.ArmFactoryResetResponse], error) {
	m := r.Msg
	at, err := h.o.Power.Arm(h.caller(ctx), m.GetId(), m.GetStartedBy(), m.GetApprovals())
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&initv1.ArmFactoryResetResponse{RunsAt: timestamppb.New(at)}), nil
}

func (h *powerHandler) CancelFactoryReset(ctx context.Context, r *connect.Request[initv1.CancelFactoryResetRequest]) (*connect.Response[initv1.CancelFactoryResetResponse], error) {
	if err := h.o.Power.Cancel(h.caller(ctx), r.Msg.GetId(), r.Msg.GetActor()); err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&initv1.CancelFactoryResetResponse{}), nil
}

func (h *powerHandler) FactoryReset(ctx context.Context, r *connect.Request[initv1.FactoryResetRequest]) (*connect.Response[initv1.FactoryResetResponse], error) {
	m := r.Msg
	if err := h.o.Power.FactoryReset(ctx, h.caller(ctx), m.GetId(), m.GetStartedBy(), m.GetApprovals()); err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&initv1.FactoryResetResponse{}), nil
}
