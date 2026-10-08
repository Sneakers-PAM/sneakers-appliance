// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

type local struct {
	osadminv1connect.UnimplementedLocalServiceHandler
	s *Server
}

// peer returns the caller's uid; the listener let only root and admin uids
// through.
func peer(ctx context.Context) (uint32, error) {
	p, ok := initapi.PeerFrom(ctx)
	if !ok {
		return 0, connect.NewError(connect.CodePermissionDenied, errors.New("the caller's credentials are unknown"))
	}
	return p.UID, nil
}

func (h *local) LocalCancelFactoryReset(ctx context.Context, r *connect.Request[osadminv1.LocalCancelFactoryResetRequest]) (*connect.Response[osadminv1.LocalCancelFactoryResetResponse], error) {
	uid, err := peer(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.s.CancelFactoryResetLocal(uid, r.Msg.GetActor()); err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&osadminv1.LocalCancelFactoryResetResponse{}), nil
}

// CancelFactoryResetLocal stops a factory reset from the console (root,
// actor "console" unless named) or a closed-shell login (an admin uid,
// acting as itself).
func (s *Server) CancelFactoryResetLocal(uid uint32, actor string) error {
	if uid != 0 {
		st := s.o.Access.Read()
		a, ok := st.AdminByUID(int(uid))
		if !ok {
			return codes.New(codes.AccessForbidden, "the caller isn't an admin")
		}
		actor = a.Name
	} else if actor == "" {
		actor = osaudit.SurfaceConsole
	}
	err := s.cancelReset("")
	s.write(osaudit.Entry{Actor: actor, Action: "power.factory-reset.cancel", Target: "box", Detail: map[string]string{"surface": osaudit.SurfaceConsole}}, err)
	return err
}
