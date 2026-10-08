// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// rootShellSvc is the root-shell code page.
type rootShellSvc struct {
	osadminv1connect.UnimplementedRootShellServiceHandler
	s *Server
}

func (h *rootShellSvc) IssueRootShellCode(ctx context.Context, r *connect.Request[osadminv1.IssueRootShellCodeRequest]) (*connect.Response[osadminv1.IssueRootShellCodeResponse], error) {
	c := callFrom(ctx)
	if h.s.o.Elevation == nil {
		return nil, notAvailable()
	}
	st := h.s.o.Access.Read()
	if !st.IsRootOperator(c.session.Admin) {
		c.note(c.session.Admin)
		return nil, codes.New(codes.AccessForbidden, "only a root operator gets a root-shell code")
	}
	a, ok := st.Admin(c.session.Admin)
	if !ok || !a.HasCredentials() {
		return nil, codes.New(codes.AccessSession, "sign in again")
	}
	// The fresh TOTP code is this action's own step-up.
	if err := h.s.checkTOTP(a, r.Msg.GetTotpCode(), c.source, osaudit.SurfaceAdmin, wrongCode); err != nil {
		c.note(c.session.Admin)
		return nil, err
	}
	req, code, err := h.s.o.Elevation.IssueCode(st, c.session.Admin, r.Msg.GetChallenge())
	c.note(req.ID, "admin", c.session.Admin, "sshSource", req.Source)
	if err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: root-shell code issued", log.F("id", req.ID), log.F("admin", c.session.Admin))
	return connect.NewResponse(&osadminv1.IssueRootShellCodeResponse{
		Code: code, Expires: timestamppb.New(*req.ValidBefore), SessionMinutes: int32(min(req.Minutes, 1<<30)), SourceAddress: req.Source, // #nosec G115 -- clamped
	}), nil
}

// BeginRootShell opens a challenge for a closed-shell login (l names the
// admin, the key and the SSH client address).
func (s *Server) BeginRootShell(l Local, reason string) (elevation.Request, error) {
	if s.o.Elevation == nil {
		return elevation.Request{}, notAvailable()
	}
	return s.o.Elevation.Challenge(s.o.Access.Read(), elevation.Caller{Admin: l.Admin, KeyFP: l.KeyFP, Source: l.Source}, reason)
}

// OpenRootShell checks a typed code; a wrong one counts toward the
// admin's lockout like a wrong TOTP code.
func (s *Server) OpenRootShell(l Local, challenge, code string) (elevation.Request, string, error) {
	if s.o.Elevation == nil {
		return elevation.Request{}, "", notAvailable()
	}
	if err := s.o.Lockout.Check(l.Admin, l.Source, s.o.Clock.Now()); err != nil {
		return elevation.Request{}, "", err
	}
	r, ticket, err := s.o.Elevation.Open(s.o.Access.Read(), elevation.Caller{Admin: l.Admin, KeyFP: l.KeyFP, Source: l.Source}, challenge, code)
	if codes.Is(err, codes.RootCode) {
		s.o.Lockout.Fail(l.Admin, l.Source, s.o.Clock.Now(), s.lockoutMode())
	}
	return r, ticket, err
}
