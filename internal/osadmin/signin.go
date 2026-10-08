// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"path/filepath"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/credentials"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/weblogin"
)

type signIn struct {
	osadminv1connect.UnimplementedSignInServiceHandler
	s *Server
}

// wrongSignIn is the one answer to a wrong name, password or code, so the
// page can't tell which.
const wrongSignIn = "that didn't work; check the name, the password and the authenticator code"

func (h *signIn) SignIn(ctx context.Context, r *connect.Request[osadminv1.SignInRequest]) (*connect.Response[osadminv1.SignInResponse], error) {
	c := callFrom(ctx)
	name := r.Msg.GetAdmin()
	c.note(name)
	st := h.s.o.Access.Read()
	a, known := st.Admin(name)
	who := ""
	if known {
		who = name
	}
	now := h.s.o.Clock.Now()
	if err := h.s.o.Lockout.Check(who, c.source, now); err != nil {
		return nil, err
	}
	if !known || !a.HasCredentials() {
		credentials.VerifyPassword(h.s.o.RootKey.Pepper(), dummyHash(), r.Msg.GetPassword())
		return nil, h.s.failed(who, c.source, osaudit.SurfaceAdmin, wrongSignIn)
	}
	if !credentials.VerifyPassword(h.s.o.RootKey.Pepper(), a.Password.Hash, r.Msg.GetPassword()) {
		return nil, h.s.failed(who, c.source, osaudit.SurfaceAdmin, wrongSignIn)
	}
	if err := h.s.checkTOTP(a, r.Msg.GetTotpCode(), c.source, osaudit.SurfaceAdmin, wrongSignIn); err != nil {
		return nil, err
	}
	// A sign-in from a browser that already holds a session for the same
	// admin replaces it.
	if old, err := h.s.session(c.header); err == nil && old.Admin == name {
		h.s.sessions.End(old.ID)
	}
	sess, notices := h.s.newSession(*a, c.source, c.userAgent)
	c.session = sess
	if h.s.FirstAdminDone() && !h.s.SetupDone() && !exists(filepath.Join(h.s.o.Paths.SetupDir(), SignedInMarker)) {
		// First boot's step 6: the admin can sign in from where they sit.
		if err := h.s.mark(SignedInMarker); err != nil {
			h.s.o.Logger.Error(err, "osadmin: the first sign-in wasn't recorded")
		} else {
			h.s.o.Logger.Info("osadmin: first sign-in recorded", log.F("admin", sess.Admin))
			h.s.consoleChanged()
		}
	}
	h.s.o.Logger.Info("osadmin: signed in", log.F("admin", sess.Admin), log.F("source", c.source))
	resp := connect.NewResponse(&osadminv1.SignInResponse{Session: h.s.toSession(sess, a.Role, notices...)})
	resp.Header().Add("Set-Cookie", sessionCookie(sess.ID, weblogin.MaxAge))
	return resp, nil
}

func (h *signIn) StepUp(ctx context.Context, r *connect.Request[osadminv1.StepUpRequest]) (*connect.Response[osadminv1.StepUpResponse], error) {
	c := callFrom(ctx)
	st := h.s.o.Access.Read()
	a, ok := st.Admin(c.session.Admin)
	if !ok || !a.HasCredentials() {
		return nil, codes.New(codes.AccessSession, "sign in again")
	}
	if err := h.s.checkTOTP(a, r.Msg.GetTotpCode(), c.source, osaudit.SurfaceAdmin, wrongCode); err != nil {
		return nil, err
	}
	sess, ok := h.s.sessions.StepUp(c.session.ID)
	if !ok {
		return nil, codes.New(codes.AccessSession, "the session has ended; sign in again")
	}
	h.s.o.Logger.Info("osadmin: stepped up", log.F("admin", sess.Admin))
	return connect.NewResponse(&osadminv1.StepUpResponse{Session: h.s.toSession(sess, c.role)}), nil
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
	resp.Header().Add("Set-Cookie", sessionCookie("", -1))
	return resp, nil
}

func (s *Server) toSession(sess weblogin.Session, role access.Role, notices ...string) *osadminv1.Session {
	return &osadminv1.Session{
		Admin: sess.Admin, Role: roleToWire(role),
		SignedIn: timestamppb.New(sess.SignedIn), StepUpUntil: timestamppb.New(sess.StepUpUntil()),
		IdleExpires: timestamppb.New(sess.IdleExpires()), Expires: timestamppb.New(sess.Expires()),
		CsrfToken: sess.CSRF, RootOperator: s.o.Access.Read().IsRootOperator(sess.Admin), Notices: notices,
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
