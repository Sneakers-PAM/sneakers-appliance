// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

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

func (h *local) DescribeSignIn(ctx context.Context, r *connect.Request[osadminv1.DescribeSignInRequest]) (*connect.Response[osadminv1.DescribeSignInResponse], error) {
	if _, err := peer(ctx); err != nil {
		return nil, err
	}
	c, err := h.s.logins.Describe(r.Msg.GetCode())
	if err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&osadminv1.DescribeSignInResponse{SourceAddress: c.Source, UserAgent: c.UserAgent, Expires: timestamppb.New(c.Expires)}), nil
}

func (h *local) ApproveSignIn(ctx context.Context, r *connect.Request[osadminv1.ApproveSignInRequest]) (*connect.Response[osadminv1.ApproveSignInResponse], error) {
	uid, err := peer(ctx)
	if err != nil {
		return nil, err
	}
	m := r.Msg
	if err := h.s.ApproveSignIn(uid, m.GetCode(), m.GetAdmin(), m.GetKeyFingerprint(), m.GetSourceAddress()); err != nil {
		return nil, toConnect(err)
	}
	return connect.NewResponse(&osadminv1.ApproveSignInResponse{}), nil
}

// ApproveSignIn binds the browser waiting on code to admin and the key
// fingerprint that authenticated the SSH session at source. uid is the
// caller's: root may approve as any admin, an admin uid only as itself.
// Every approval, allowed or refused, is audited.
func (s *Server) ApproveSignIn(uid uint32, code, admin, keyFP, source string) error {
	entry := osaudit.Entry{Actor: admin, KeyFP: keyFP, Source: source, Action: "signin.approve", Detail: map[string]string{"surface": "ssh"}}
	err := s.approve(uid, code, admin, keyFP, entry.Detail)
	entry.Outcome = "ok"
	if err != nil {
		entry.Outcome, entry.Code = "refused", symbolOf(err)
	}
	if aerr := s.o.Audit.Append(entry); aerr != nil {
		s.o.Logger.Error(aerr, "osadmin: audit append failed", log.F("action", entry.Action))
	}
	if err != nil {
		s.o.Logger.Warn("osadmin: sign-in approval refused", log.F("admin", admin), log.F("error", describe(err)))
		return err
	}
	s.o.Logger.Info("osadmin: sign-in approved", log.F("admin", admin))
	return nil
}

func (s *Server) approve(uid uint32, code, admin, keyFP string, detail map[string]string) error {
	st := s.o.Access.Read()
	a, ok := st.Admin(admin)
	if !ok {
		return codes.New(codes.AccessForbidden, "there is no admin named %q", admin)
	}
	if uid != 0 && int64(uid) != int64(a.UID) {
		return codes.New(codes.AccessForbidden, "a closed-shell login approves sign-ins only as itself")
	}
	if !hasKey(a, keyFP) {
		return codes.New(codes.AccessForbidden, "that key isn't one of %s's keys", a.Name)
	}
	c, err := s.logins.Describe(code)
	if err != nil {
		return err
	}
	detail["browser"], detail["userAgent"] = c.Source, c.UserAgent
	return s.logins.Approve(code, a.Name, keyFP)
}
