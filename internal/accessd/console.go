// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd

import (
	"context"
	"sync"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// WatchInterval is the longest the console info stream goes without a
// send.
const WatchInterval = 30 * time.Second

// watchers wake the console info streams when what they show changes.
type watchers struct {
	mu   sync.Mutex
	wake chan struct{}
}

func (w *watchers) changed() <-chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.wake == nil {
		w.wake = make(chan struct{})
	}
	return w.wake
}

func (w *watchers) notify() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.wake != nil {
		close(w.wake)
		w.wake = nil
	}
}

// ConsoleChanged wakes every console info stream: the :8443 API's
// OnConsoleChange.
func (s *Server) ConsoleChanged() { s.console.notify() }

// consoleInfo is what the console shows now.
func (s *Server) consoleInfo(ctx context.Context) *accessv1.ConsoleInfo {
	var mgmt []string
	host := ""
	if s.o.Network != nil {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		if ns, err := s.o.Network.Status(cctx, connect.NewRequest(&netdv1.StatusRequest{})); err == nil {
			mgmt, host = Bindable(ns.Msg.GetManagementAddresses()), ns.Msg.GetHostname()
		} else {
			s.o.Logger.Warn("accessd: netd didn't give the addresses for the console", log.F("error", err.Error()))
		}
		cancel()
	}
	return s.api.ConsoleInfo(ctx, mgmt, host)
}

// console checks the caller is root, the console.
func (h *setupH) console(ctx context.Context, procedure string) error {
	l, err := h.s.caller(ctx, nil, procedure)
	if err != nil {
		return err
	}
	if l.Admin != "" {
		return refuse(codes.New(codes.AccessForbidden, "this is done on the console"))
	}
	return nil
}

func (h *setupH) GetConsoleInfo(ctx context.Context, _ *connect.Request[accessv1.GetConsoleInfoRequest]) (*connect.Response[accessv1.GetConsoleInfoResponse], error) {
	if err := h.console(ctx, accessv1connect.SetupServiceGetConsoleInfoProcedure); err != nil {
		return nil, err
	}
	return connect.NewResponse(&accessv1.GetConsoleInfoResponse{ConsoleInfo: h.s.consoleInfo(ctx)}), nil
}

func (h *setupH) WatchConsoleInfo(ctx context.Context, _ *connect.Request[accessv1.WatchConsoleInfoRequest], stream *connect.ServerStream[accessv1.WatchConsoleInfoResponse]) error {
	if err := h.console(ctx, accessv1connect.SetupServiceWatchConsoleInfoProcedure); err != nil {
		return err
	}
	h.s.o.Logger.Debug("accessd: a console watches the console info")
	for {
		wake := h.s.console.changed()
		if err := stream.Send(&accessv1.WatchConsoleInfoResponse{ConsoleInfo: h.s.consoleInfo(ctx)}); err != nil {
			return err
		}
		t := time.NewTimer(WatchInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-wake:
		case <-t.C:
		}
		t.Stop()
	}
}

func (h *setupH) ResetSetupCode(ctx context.Context, _ *connect.Request[accessv1.ResetSetupCodeRequest]) (*connect.Response[accessv1.ResetSetupCodeResponse], error) {
	if err := h.console(ctx, accessv1connect.SetupServiceResetSetupCodeProcedure); err != nil {
		return nil, err
	}
	h.s.api.ResetSetupCode()
	return connect.NewResponse(&accessv1.ResetSetupCodeResponse{ConsoleInfo: h.s.consoleInfo(ctx)}), nil
}

func (h *setupH) BeginRecoverAccess(ctx context.Context, _ *connect.Request[accessv1.BeginRecoverAccessRequest]) (*connect.Response[accessv1.BeginRecoverAccessResponse], error) {
	if err := h.console(ctx, accessv1connect.SetupServiceBeginRecoverAccessProcedure); err != nil {
		return nil, err
	}
	code, expires := h.s.api.BeginRecoverAccess()
	rec := &accessv1.RecoverAccess{Code: code, Expires: timestamppb.New(expires), AttemptsLeft: 5}
	if info := h.s.consoleInfo(ctx); info.GetRecover() != nil {
		rec.Url, rec.AttemptsLeft = info.GetRecover().GetUrl(), info.GetRecover().GetAttemptsLeft()
	}
	return connect.NewResponse(&accessv1.BeginRecoverAccessResponse{Recover: rec}), nil
}

func (h *setupH) CancelRecoverAccess(ctx context.Context, _ *connect.Request[accessv1.CancelRecoverAccessRequest]) (*connect.Response[accessv1.CancelRecoverAccessResponse], error) {
	if err := h.console(ctx, accessv1connect.SetupServiceCancelRecoverAccessProcedure); err != nil {
		return nil, err
	}
	h.s.api.CancelRecoverAccess()
	return connect.NewResponse(&accessv1.CancelRecoverAccessResponse{}), nil
}
