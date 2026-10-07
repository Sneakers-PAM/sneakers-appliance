// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"connectrpc.com/connect"

	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Services is the shell's backend on the box. The access commands and the
// sign-in approval go to accessd on access.sock, which knows the login by
// its uid; reboot and poweroff go to init's PowerService on power.sock,
// always graceful (init checks it's the shell asking); the commands of
// later specs answer "Not available in this release". While accessd is
// down its commands say the appliance services are unavailable, and
// status shows the last status accessd kept.
type Services struct {
	Session Session
	// SessionErr is why Session couldn't be read; a sign-in approval needs
	// the session's key, so it's refused.
	SessionErr error
	Local      osadminv1connect.LocalServiceClient
	Power      initv1connect.PowerServiceClient
	// The accessd clients (UseAccessd sets them all); nil means accessd
	// isn't reachable.
	Access    accessv1connect.AccessServiceClient
	Network   accessv1connect.NetworkServiceClient
	Setup     accessv1connect.SetupServiceClient
	Elevation accessv1connect.ElevationServiceClient
	// StatusFile is accessd's status cache (accessapi.StatusFile).
	StatusFile string
}

// ErrNotInRelease is the answer of a command whose backend isn't on the box.
var ErrNotInRelease = codes.New(codes.NotAvailable, "Not available in this release.")

// maxShown bounds what the prompt shows of a browser-supplied string.
const maxShown = 200

// Call carries out r.
func (s *Services) Call(ctx context.Context, r Request) (Result, error) {
	switch {
	case r.Action == "login.lookup":
		return s.lookup(ctx, r.Args[0])
	case r.Action == "login.approve":
		return s.approve(ctx, r.Args[0])
	case (r.Action == "power.reboot" || r.Action == "power.off") && s.Power != nil:
		return s.power(ctx, r.Action)
	case laterAction(r.Action):
		return Result{}, ErrNotInRelease
	}
	if res, ok, err := s.accessd(ctx, r); ok {
		return res, err
	}
	return Result{}, ErrUnavailable
}

func (s *Services) lookup(ctx context.Context, code string) (Result, error) {
	if s.SessionErr != nil || s.Session.KeyFingerprint == "" {
		return Result{}, codes.New(codes.AccessForbidden, "this login can't approve a sign-in: sshd didn't say which key signed in")
	}
	if s.Local == nil {
		return Result{}, ErrUnavailable
	}
	resp, err := s.Local.DescribeSignIn(ctx, connect.NewRequest(&osadminv1.DescribeSignInRequest{Code: code}))
	if err != nil {
		return Result{}, fromAccessd(err)
	}
	m := resp.Msg
	return Result{Text: fmt.Sprintf("Sign in the browser at %s (%s) as %s?", Printable(m.GetSourceAddress()), Printable(m.GetUserAgent()), s.Session.Admin)}, nil
}

func (s *Services) approve(ctx context.Context, code string) (Result, error) {
	_, err := s.Local.ApproveSignIn(ctx, connect.NewRequest(&osadminv1.ApproveSignInRequest{
		Code: code, Admin: s.Session.Admin, KeyFingerprint: s.Session.KeyFingerprint, SourceAddress: s.Session.Source,
	}))
	if err != nil {
		return Result{}, fromAccessd(err)
	}
	return Result{Text: "Signed in. The browser continues on its own.", Data: map[string]string{"signedIn": s.Session.Admin}}, nil
}

func (s *Services) power(ctx context.Context, action string) (Result, error) {
	var err error
	text := "Rebooting. The services are stopping first."
	if action == "power.off" {
		text = "Shutting down. The services are stopping first."
		_, err = s.Power.PowerOff(ctx, connect.NewRequest(&initv1.PowerOffRequest{}))
	} else {
		_, err = s.Power.Reboot(ctx, connect.NewRequest(&initv1.RebootRequest{}))
	}
	if err != nil {
		return Result{}, fromDaemon(err, "init")
	}
	return Result{Text: text}, nil
}

// Printable makes a string from the network safe to show on a terminal:
// control characters (escape sequences among them) become '?', and it's cut
// to a couple of hundred characters.
func Printable(v string) string {
	var b strings.Builder
	n := 0
	for _, r := range v {
		if n == maxShown {
			b.WriteString("...")
			break
		}
		if !unicode.IsPrint(r) {
			r = '?'
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// fromDaemon turns a daemon's Connect error into the coded error its
// message names.
func fromDaemon(err error, who string) error {
	ce := new(connect.Error)
	if !errors.As(err, &ce) {
		return codes.Wrap(codes.NotAvailable, fmt.Errorf("%s isn't answering; try again shortly: %w", who, err))
	}
	switch ce.Code() {
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeCanceled:
		return codes.Wrap(codes.NotAvailable, fmt.Errorf("%s isn't answering; try again shortly", who))
	case connect.CodeUnimplemented:
		return ErrNotInRelease
	}
	msg := ce.Message()
	for _, e := range codes.Entries {
		if prefix := fmt.Sprintf("%s (%d): ", e.Symbol, e.Code); strings.HasPrefix(msg, prefix) {
			return codes.New(e.Code, "%s", strings.TrimPrefix(msg, prefix))
		}
	}
	return remoteError{msg}
}

// remoteError is a daemon's refusal that carries no code; it's shown as is.
type remoteError struct{ msg string }

func (e remoteError) Error() string { return e.msg }
