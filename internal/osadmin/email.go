// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"strconv"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsettings"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/edgefall"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// EmailSettings keep the product's mail relay (boxsettings.Store on the
// box).
type EmailSettings interface {
	Email() (boxsettings.Email, error)
	SetEmail(boxsettings.Email) error
}

// EmailWorkloads restart the workloads that read the email settings once
// k0s has applied them.
type EmailWorkloads interface {
	// Applied waits until k0s has applied the box secrets stack as it is
	// on disk now.
	Applied(ctx context.Context) error
	// Restart restarts one workload.
	Restart(ctx context.Context, ns, kind, name string) error
}

// emailRestartBound is how long the restart after a change waits for the
// product to come back and take the settings.
const emailRestartBound = ProductUpBound

type emailSvc struct {
	osadminv1connect.UnimplementedEmailServiceHandler
	s *Server
}

var tlsWords = map[osadminv1.EmailTls]string{
	osadminv1.EmailTls_EMAIL_TLS_NONE:     boxsettings.TLSNone,
	osadminv1.EmailTls_EMAIL_TLS_STARTTLS: boxsettings.TLSStartTLS,
	osadminv1.EmailTls_EMAIL_TLS_IMPLICIT: boxsettings.TLSImplicit,
}

func tlsOf(word string) osadminv1.EmailTls {
	for k, v := range tlsWords {
		if v == word {
			return k
		}
	}
	return osadminv1.EmailTls_EMAIL_TLS_UNSPECIFIED
}

func toWire(e boxsettings.Email) *osadminv1.EmailSettings {
	return &osadminv1.EmailSettings{Host: e.Host, Port: uint32(max(e.Port, 0)), From: e.From, Username: e.Username, Tls: tlsOf(e.TLS), Verify: e.Verify, CaPem: e.CA} // #nosec G115 -- a port, 0 to 65535
}

// fromWire is the settings in w, the password from password when given,
// else kept; an unknown TLS mode stays unknown, so Check refuses it.
func fromWire(w *osadminv1.EmailSettings, password *string, saved boxsettings.Email) boxsettings.Email {
	e := boxsettings.Email{Host: w.GetHost(), Port: int(w.GetPort()), From: w.GetFrom(), Username: w.GetUsername(), TLS: tlsWords[w.GetTls()], Verify: w.GetVerify(), CA: w.GetCaPem()}
	if e.TLS == "" {
		e.TLS = w.GetTls().String()
	}
	switch {
	case password != nil:
		e.Password = *password
	case e.Username != "":
		e.Password = saved.Password
	}
	return e
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// emailProduct is the installed product when it reads email settings.
func (s *Server) emailProduct() (string, productspec.Spec, error) {
	info, spec := s.installedSpec()
	switch {
	case !info.Present():
		return "", spec, codes.New(codes.NotAvailable, "no product is installed")
	case !spec.ReadsEmail():
		return info.Title, spec, codes.New(codes.NotAvailable, "%s reads no email settings", info.Title)
	case s.o.Email == nil:
		return info.Title, spec, codes.New(codes.NotAvailable, "this box keeps no email settings")
	}
	return info.Title, spec, nil
}

// GetEmail is the saved relay, without its password.
func (h *emailSvc) GetEmail(context.Context, *connect.Request[osadminv1.GetEmailRequest]) (*connect.Response[osadminv1.GetEmailResponse], error) {
	s := h.s
	out := &osadminv1.GetEmailResponse{State: "not installed", Settings: toWire(boxsettings.DefaultEmail())}
	info, spec := s.installedSpec()
	switch {
	case !info.Present():
		return connect.NewResponse(out), nil
	case !spec.ReadsEmail() || s.o.Email == nil:
		out.State = "not in this product"
		return connect.NewResponse(out), nil
	}
	e, err := s.o.Email.Email()
	if err != nil {
		return nil, err
	}
	out.State, out.Settings, out.PasswordSet, out.Label, out.Encrypted = "not set", toWire(e), e.Password != "", spec.Email.Label, e.Encrypted()
	if e.Configured() {
		out.State = "set"
	}
	return connect.NewResponse(out), nil
}

// SetEmail saves the relay and applies the product again with it, under
// the maintenance gate; the workloads that read the settings restart once
// k0s has applied them.
func (h *emailSvc) SetEmail(ctx context.Context, r *connect.Request[osadminv1.SetEmailRequest]) (*connect.Response[osadminv1.SetEmailResponse], error) {
	s, c := h.s, callFrom(ctx)
	_, spec, err := s.emailProduct()
	if err != nil {
		return nil, err
	}
	saved, err := s.o.Email.Email()
	if err != nil {
		return nil, err
	}
	e := fromWire(r.Msg.GetSettings(), r.Msg.Password, saved)
	pw := "none"
	switch {
	case r.Msg.Password != nil && *r.Msg.Password != "":
		pw = "set"
	case r.Msg.Password != nil && saved.Password != "":
		pw = "cleared"
	case e.Password != "":
		pw = "kept"
	}
	ca := "none"
	if e.CA != "" {
		ca = "set"
	}
	c.note("product email", "host", e.Host, "port", strconv.Itoa(e.Port), "from", e.From, "username", e.Username, "tls", e.TLS, "verify", onOff(e.Verify), "ca", ca, "password", pw)
	if err := e.Check(); err != nil {
		return nil, err
	}
	by := c.by("product.email.set")
	v := s.slots().Status().Installed
	overrode, err := s.beginMaintenance(ctx, "product email settings apply", edgefall.KindProductApply, by, r.Msg.GetElevationOverride())
	if err != nil {
		return nil, err
	}
	if overrode != "" {
		c.note("product email", "overrode", overrode)
	}
	if err := s.o.Email.SetEmail(e); err != nil {
		s.endMaintenance()
		return nil, err
	}
	if !e.Encrypted() && e.Configured() {
		s.o.Logger.Warn("osadmin: the product's mail goes to its relay unencrypted or to a relay that isn't verified", log.F("tls", e.TLS), log.F("verify", e.Verify), log.F("by", c.session.Admin))
	}
	s.o.Logger.Info("osadmin: the product's email settings are saved; the product is applied again", log.F("host", e.Host), log.F("port", e.Port), log.F("tls", e.TLS), log.F("verify", e.Verify), log.F("password", pw), log.F("version", v), log.F("by", c.session.Admin))
	s.continueApply(osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT, v, "")
	err = s.switchProduct(ctx, s.slots().Current(), func() error { return nil })
	s.endMaintenance()
	s.productHistory("apply", v, c.session.Admin, err, "email settings")
	if err != nil {
		s.o.Logger.Error(err, "osadmin: the product wasn't applied again with the email settings")
		return nil, err
	}
	s.restartEmailReaders(spec)
	return connect.NewResponse(&osadminv1.SetEmailResponse{}), nil
}

// restartEmailReaders restarts the workloads the product names for its
// email settings once k0s has applied them, in the background.
func (s *Server) restartEmailReaders(spec productspec.Spec) {
	if s.o.EmailWorkloads == nil || spec.Email == nil || len(spec.Email.Restart) == 0 {
		return
	}
	w, lg := s.o.EmailWorkloads, s.o.Logger
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), emailRestartBound)
		defer cancel()
		started := time.Now()
		if err := w.Applied(ctx); err != nil {
			lg.Warn("osadmin: k0s hasn't applied the email settings yet; restarting their readers anyway", log.F("error", err.Error()))
		}
		for i := range spec.Email.Restart {
			ns, kind, name, _ := spec.Email.RestartRef(i)
			if err := w.Restart(ctx, ns, kind, name); err != nil {
				lg.Warn("osadmin: a workload didn't restart; it reads the email settings at its next start", log.F("workload", spec.Email.Restart[i]), log.F("error", err.Error()))
				continue
			}
			lg.Info("osadmin: restarted for the email settings", log.F("workload", spec.Email.Restart[i]), log.F("ms", time.Since(started).Milliseconds()))
		}
	}()
}

// SendTestEmail sends one message through the settings given, or the
// saved ones.
func (h *emailSvc) SendTestEmail(ctx context.Context, r *connect.Request[osadminv1.SendTestEmailRequest]) (*connect.Response[osadminv1.SendTestEmailResponse], error) {
	s, c := h.s, callFrom(ctx)
	if _, _, err := s.emailProduct(); err != nil {
		return nil, err
	}
	saved, err := s.o.Email.Email()
	if err != nil {
		return nil, err
	}
	e := saved
	if r.Msg.GetSettings() != nil {
		e = fromWire(r.Msg.GetSettings(), r.Msg.Password, saved)
	} else if r.Msg.Password != nil {
		e.Password = *r.Msg.Password
	}
	c.note("product email", "to", r.Msg.GetTo(), "host", e.Host, "port", strconv.Itoa(e.Port), "tls", e.TLS, "verify", onOff(e.Verify))
	send := s.o.SendEmail
	if send == nil {
		send = boxsettings.Send
	}
	started := time.Now()
	answer, err := send(ctx, e, r.Msg.GetTo())
	s.o.Logger.Info("osadmin: test email", log.F("host", e.Host), log.F("port", e.Port), log.F("tls", e.TLS), log.F("ms", time.Since(started).Milliseconds()), log.F("ok", err == nil), log.F("by", c.session.Admin))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&osadminv1.SendTestEmailResponse{Answer: answer}), nil
}
