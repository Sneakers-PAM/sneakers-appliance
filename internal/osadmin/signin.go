// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"net/http"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

type signIn struct {
	osadminv1connect.UnimplementedSignInServiceHandler
	s *Server
}

func (h *signIn) BeginSignIn(ctx context.Context, _ *connect.Request[osadminv1.BeginSignInRequest]) (*connect.Response[osadminv1.BeginSignInResponse], error) {
	c := callFrom(ctx)
	code, err := h.s.logins.Begin(c.source, c.userAgent)
	if err != nil {
		return nil, err
	}
	h.s.o.Logger.Info("osadmin: sign-in code issued", log.F("source", c.source))
	return connect.NewResponse(&osadminv1.BeginSignInResponse{
		Code: code.Code, PollToken: code.PollToken, Expires: timestamppb.New(code.Expires),
		SourceAddress: code.Source, UserAgent: code.UserAgent,
	}), nil
}

func (h *signIn) PollSignIn(ctx context.Context, r *connect.Request[osadminv1.PollSignInRequest]) (*connect.Response[osadminv1.PollSignInResponse], error) {
	c := callFrom(ctx)
	state, ap := h.s.logins.Poll(r.Msg.GetPollToken())
	switch state {
	case weblogin.Pending:
		return connect.NewResponse(&osadminv1.PollSignInResponse{State: osadminv1.SignInState_SIGN_IN_STATE_PENDING}), nil
	case weblogin.Expired:
		return connect.NewResponse(&osadminv1.PollSignInResponse{State: osadminv1.SignInState_SIGN_IN_STATE_EXPIRED}), nil
	}
	st := h.s.o.Access.Read()
	a, ok := st.Admin(ap.Admin)
	if !ok || !hasKey(a, ap.KeyFP) {
		return nil, codes.New(codes.LoginCode, "the admin or key that approved this sign-in was removed")
	}
	// A sign-in from a browser that already holds a session for the same
	// admin is a step-up: the new session replaces the old one.
	if old, err := h.s.session(c.header); err == nil && old.Admin == ap.Admin {
		h.s.sessions.End(old.ID)
	}
	sess := h.s.sessions.Create(ap.Admin, ap.KeyFP, ap.Source, ap.UserAgent)
	h.s.write(osaudit.Entry{Actor: sess.Admin, KeyFP: sess.KeyFP, Source: c.source, Action: "signin.session.start"}, nil)
	h.s.o.Logger.Info("osadmin: signed in", log.F("admin", sess.Admin), log.F("source", c.source))
	resp := connect.NewResponse(&osadminv1.PollSignInResponse{State: osadminv1.SignInState_SIGN_IN_STATE_APPROVED, Session: h.s.toSession(sess, a.Role)})
	resp.Header().Add("Set-Cookie", (&http.Cookie{
		Name: CookieName, Value: sess.ID, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(weblogin.MaxAge.Seconds()),
	}).String())
	return resp, nil
}

func (h *signIn) GetSession(ctx context.Context, _ *connect.Request[osadminv1.GetSessionRequest]) (*connect.Response[osadminv1.GetSessionResponse], error) {
	c := callFrom(ctx)
	return connect.NewResponse(&osadminv1.GetSessionResponse{Session: h.s.toSession(c.session, c.role)}), nil
}

func (h *signIn) SignOut(ctx context.Context, _ *connect.Request[osadminv1.SignOutRequest]) (*connect.Response[osadminv1.SignOutResponse], error) {
	c := callFrom(ctx)
	h.s.sessions.End(c.session.ID)
	h.s.o.Logger.Info("osadmin: signed out", log.F("admin", c.session.Admin))
	resp := connect.NewResponse(&osadminv1.SignOutResponse{})
	resp.Header().Add("Set-Cookie", (&http.Cookie{Name: CookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1}).String())
	return resp, nil
}

func (s *Server) toSession(sess weblogin.Session, role access.Role) *osadminv1.Session {
	return &osadminv1.Session{
		Admin: sess.Admin, Role: roleToWire(role), KeyFingerprint: sess.KeyFP,
		SignedIn: timestamppb.New(sess.SignedIn), StepUpUntil: timestamppb.New(sess.StepUpUntil()),
		IdleExpires: timestamppb.New(sess.IdleExpires()), Expires: timestamppb.New(sess.Expires()),
		CsrfToken: sess.CSRF,
	}
}

func roleToWire(r access.Role) osadminv1.Role {
	switch r {
	case access.RoleOwner:
		return osadminv1.Role_ROLE_OWNER
	case access.RoleAdmin:
		return osadminv1.Role_ROLE_ADMIN
	}
	return osadminv1.Role_ROLE_UNSPECIFIED
}

func roleFromWire(r osadminv1.Role) (access.Role, error) {
	switch r {
	case osadminv1.Role_ROLE_OWNER:
		return access.RoleOwner, nil
	case osadminv1.Role_ROLE_ADMIN:
		return access.RoleAdmin, nil
	}
	return "", codes.New(codes.AccessName, "choose the owner or admin role")
}
