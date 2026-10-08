// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"net"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// ConsoleInfo is what the console shows about access: the setup code or
// setup's progress, :8443's address and certificate, and a live Recover
// access code. mgmt are the management addresses and hostname the box's
// host name, as netd reports them.
func (s *Server) ConsoleInfo(ctx context.Context, mgmt []string, hostname string) *accessv1.ConsoleInfo {
	s.expireSetupSession()
	st := s.o.Access.Read()
	out := &accessv1.ConsoleInfo{SetupSteps: 6, HostKeys: s.hostKeys(), Updated: timestamppb.New(s.o.Clock.Now())}
	for _, a := range mgmt {
		out.Urls = append(out.Urls, "https://"+net.JoinHostPort(a, "8443"))
	}
	if len(out.Urls) > 0 {
		out.Url = out.Urls[0]
	}
	out.CertFingerprint = strings.ToUpper(strings.ReplaceAll(s.cert().Fingerprint, ":", ""))
	if strings.Contains(strings.Trim(hostname, "."), ".") {
		out.Fqdn = strings.TrimSuffix(hostname, ".")
	}
	for _, a := range st.Admins {
		if a.CreatedBy == "setup" {
			out.FirstAdmin = a.Name
		}
		if a.HasCredentials() {
			out.SshOn = true
		}
	}
	steps := s.setupSteps()
	n, kind := currentStep(steps)
	switch {
	case s.SetupDone():
		out.State = accessv1.SetupState_SETUP_STATE_DONE
	case s.FirstAdminDone():
		out.State = accessv1.SetupState_SETUP_STATE_IN_PROGRESS
	default:
		sc := s.codes.Setup()
		if sc.InUse {
			out.State, out.SetupSource, out.SetupStarted = accessv1.SetupState_SETUP_STATE_IN_PROGRESS, sc.Source, timestamppb.New(sc.Started)
		} else {
			out.State, out.SetupCode, out.CodeExpires = accessv1.SetupState_SETUP_STATE_NOT_STARTED, sc.Value, timestamppb.New(sc.Expires)
			out.AttemptsLeft = int32(min(sc.AttemptsLeft, 1<<30)) // #nosec G115 -- clamped
			out.CodeLocked = sc.Locked
		}
	}
	if out.State == accessv1.SetupState_SETUP_STATE_IN_PROGRESS {
		out.SetupStep, out.SetupStepKind = n, kind
		if out.SetupSource == "" {
			if cs, ok := s.liveSetupSession(); ok {
				out.SetupSource, out.SetupStarted = cs.Source, timestamppb.New(cs.Started)
			}
		}
	}
	if r, ok := s.codes.Recover(); ok {
		rec := &accessv1.RecoverAccess{Code: r.Value, Expires: timestamppb.New(r.Expires), AttemptsLeft: int32(min(r.AttemptsLeft, 1<<30)), InUse: r.InUse, Source: r.Source} // #nosec G115 -- clamped
		if out.Url != "" {
			rec.Url = out.Url + "/recover"
		}
		if r.InUse {
			rec.Code = ""
		}
		out.Recover = rec
	}
	return out
}

// ResetSetupCode is the console's "this isn't you": the browser holding the
// setup code is stopped and a new code shown, until the first admin exists.
func (s *Server) ResetSetupCode() {
	if s.FirstAdminDone() {
		return
	}
	n := s.endSetupSessions()
	s.codes.ResetSetup()
	s.write(osaudit.Entry{Actor: osaudit.SurfaceConsole, Action: "setup.code.reset", Detail: map[string]string{"surface": osaudit.SurfaceConsole, "sessionsEnded": itoa(n)}}, nil)
	s.o.Logger.Info("osadmin: the console stopped the browser setup and showed a new code", log.F("sessionsEnded", n))
}

// BeginRecoverAccess issues the console's Recover access code.
func (s *Server) BeginRecoverAccess() (string, time.Time) {
	r := s.codes.BeginRecover()
	s.write(osaudit.Entry{Actor: osaudit.SurfaceConsole, Action: "recover-access.code", Detail: map[string]string{"surface": osaudit.SurfaceConsole, "expires": r.Expires.UTC().Format(time.RFC3339)}}, nil)
	s.o.Logger.Info("osadmin: a Recover access code is out")
	return r.Value, r.Expires
}

// CancelRecoverAccess withdraws it.
func (s *Server) CancelRecoverAccess() {
	s.codes.CancelRecover()
	s.write(osaudit.Entry{Actor: osaudit.SurfaceConsole, Action: "recover-access.cancel", Detail: map[string]string{"surface": osaudit.SurfaceConsole}}, nil)
}

// HasSignInAdmin reports whether an admin can sign in: sshd may run.
func HasSignInAdmin(st access.State) bool {
	for i := range st.Admins {
		if st.Admins[i].HasCredentials() {
			return true
		}
	}
	return false
}
