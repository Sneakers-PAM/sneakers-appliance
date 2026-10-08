// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"slices"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/onetime"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// SSHLogin is a closed-shell login that passed its TOTP check.
type SSHLogin struct {
	ID           string
	Admin        string
	Role         access.Role
	RootOperator bool
}

// VerifyLoginTotp is the closed shell's first act: l is the login (the
// admin of its uid, the key sshd authenticated, the SSH client address).
// The key must be one of the admin's issued keys, still valid, and code a
// fresh TOTP code, under the same lockout and throttling as :8443. Every
// check is audited.
func (s *Server) VerifyLoginTotp(l Local, code string) (SSHLogin, error) {
	out, err := s.verifyLogin(l, code)
	e := osaudit.Entry{Actor: l.Admin, KeyFP: l.KeyFP, Source: l.Source, Action: "ssh.login", Target: sessionName(l.Admin, "SSH login", l.Source), Detail: map[string]string{"surface": SurfaceSSH}}
	if out.ID != "" {
		e.Detail["login"] = out.ID
	}
	s.write(e, err)
	if err != nil {
		s.o.Logger.Warn("osadmin: an SSH login's TOTP check refused", log.F("admin", l.Admin), log.F("source", l.Source), log.F("error", describe(err)))
		return out, err
	}
	s.o.Logger.Info("osadmin: SSH login", log.F("admin", l.Admin), log.F("source", l.Source), log.F("login", out.ID))
	return out, nil
}

func (s *Server) verifyLogin(l Local, code string) (SSHLogin, error) {
	st := s.o.Access.Read()
	a, ok := st.Admin(l.Admin)
	if !ok || !a.HasCredentials() {
		return SSHLogin{}, codes.New(codes.AccessForbidden, "this login isn't an admin who can sign in")
	}
	now := s.o.Clock.Now()
	i := slices.IndexFunc(a.Keys, func(k access.AdminKey) bool { return k.Fingerprint == l.KeyFP })
	if l.KeyFP == "" || i < 0 {
		return SSHLogin{}, codes.New(codes.AccessForbidden, "sshd didn't name an issued key of %s for this login", a.Name)
	}
	if k := a.Keys[i]; k.ValidBefore != nil && !now.Before(*k.ValidBefore) {
		return SSHLogin{}, codes.New(codes.AccessForbidden, "the key %s expired; get a new one on :8443", l.KeyFP)
	}
	if err := s.checkTOTP(a, code, l.Source, SurfaceSSH, wrongCode); err != nil {
		return SSHLogin{}, err
	}
	utc := now.UTC()
	if err := s.o.Access.Update(func(st *access.State) error {
		if x, ok := st.Admin(l.Admin); ok {
			x.LastSignIn = &utc
			for j := range x.Keys {
				if x.Keys[j].Fingerprint == l.KeyFP {
					x.Keys[j].LastUsed = &utc
				}
			}
		}
		return nil
	}); err != nil {
		s.o.Logger.Warn("osadmin: the login time wasn't recorded", log.F("admin", l.Admin), log.F("error", describe(err)))
	}
	return SSHLogin{ID: "L-" + onetime.New(8), Admin: a.Name, Role: a.Role, RootOperator: st.IsRootOperator(a.Name)}, nil
}

// EndSSHLogin records a login's end.
func (s *Server) EndSSHLogin(l Local, id string) {
	s.write(osaudit.Entry{Actor: l.Admin, KeyFP: l.KeyFP, Source: l.Source, Action: "ssh.logout", Target: sessionName(l.Admin, "SSH login", l.Source), Detail: map[string]string{"login": id, "surface": SurfaceSSH}}, nil)
}
