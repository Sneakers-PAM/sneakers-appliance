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

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Services is the shell's backend on the box. The TOTP check, the access
// commands and the root shell go to accessd on access.sock, which knows
// the login by its uid; reboot and poweroff go to init's PowerService on power.sock,
// always graceful (init checks it's the shell asking); the commands of
// later specs answer "Not available in this release". While accessd is
// down its commands say the appliance services are unavailable, and
// status shows the last status accessd kept.
type Services struct {
	Session Session
	// SessionErr is why Session couldn't be read; the TOTP check needs the
	// session's key, so the login is refused.
	SessionErr error
	Local      osadminv1connect.LocalServiceClient
	Power      initv1connect.PowerServiceClient
	// The accessd clients (UseAccessd sets them all); nil means accessd
	// isn't reachable.
	Access    accessv1connect.AccessServiceClient
	Network   accessv1connect.NetworkServiceClient
	Setup     accessv1connect.SetupServiceClient
	Elevation accessv1connect.ElevationServiceClient
	SSHLogin  accessv1connect.SshLoginServiceClient
	// Reset is the access service for the product reset, on a client
	// whose timeout lets it finish (UseResetClient); nil uses Access.
	Reset accessv1connect.AccessServiceClient
	// StatusFile is accessd's status cache (accessapi.StatusFile).
	StatusFile string
	// Role is the login's role once VerifyTotp passed: owner or admin.
	Role string
}

// ErrNotInRelease is the answer of a command whose backend isn't on the box.
var ErrNotInRelease = codes.New(codes.NotAvailable, "Not available in this release.")

// maxShown bounds what the prompt shows of a browser-supplied string.
const maxShown = 200

// Call carries out r.
func (s *Services) Call(ctx context.Context, r Request) (Result, error) {
	switch {
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

// VerifyTotp is the login's first act: the admin's TOTP code, checked by
// accessd under the lockout. It returns the login's id for the audit log.
func (s *Services) VerifyTotp(ctx context.Context, code string) (string, error) {
	if s.SessionErr != nil || s.Session.KeyFingerprint == "" {
		return "", codes.New(codes.AccessForbidden, "this login can't be checked: sshd didn't say which key signed in")
	}
	if s.SSHLogin == nil {
		return "", ErrUnavailable
	}
	out, err := s.SSHLogin.VerifyTotp(ctx, connect.NewRequest(&accessv1.VerifyTotpRequest{TotpCode: code}))
	if err != nil {
		return "", fromAccessd(err)
	}
	s.Role = roleWord(out.Msg.GetRole())
	return out.Msg.GetLoginId(), nil
}

// EndLogin records the login's end.
func (s *Services) EndLogin(ctx context.Context, id string) {
	if s.SSHLogin != nil && id != "" {
		_, _ = s.SSHLogin.EndSshLogin(ctx, connect.NewRequest(&accessv1.EndSshLoginRequest{LoginId: id}))
	}
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
