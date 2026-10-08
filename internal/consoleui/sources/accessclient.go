// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"sync"
	"time"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
)

// watchRetry is how long the console waits before it watches accessd's
// console info again after the stream ended.
const watchRetry = 2 * time.Second

// AccessConsole is the access backend's console API on accessd's socket:
// GetConsoleInfo for each read, and WatchConsoleInfo (Watch) to redraw the
// screen as soon as anything changes.
type AccessConsole struct {
	Setup accessv1connect.SetupServiceClient

	once    sync.Once
	changed chan struct{}
}

func (a *AccessConsole) ch() chan struct{} {
	a.once.Do(func() { a.changed = make(chan struct{}, 1) })
	return a.changed
}

// Read returns the info.
func (a *AccessConsole) Read(ctx context.Context) (ConsoleInfo, error) {
	r, err := a.Setup.GetConsoleInfo(ctx, connect.NewRequest(&accessv1.GetConsoleInfoRequest{}))
	if err != nil {
		return ConsoleInfo{}, err
	}
	return fromWire(r.Msg.GetConsoleInfo()), nil
}

// Changed is signalled on every update Watch receives.
func (a *AccessConsole) Changed() <-chan struct{} { return a.ch() }

// Watch follows accessd's console info until ctx ends, signalling Changed
// on every update, and watches again when the stream ends.
func (a *AccessConsole) Watch(ctx context.Context) {
	changed := a.ch()
	for ctx.Err() == nil {
		if s, err := a.Setup.WatchConsoleInfo(ctx, connect.NewRequest(&accessv1.WatchConsoleInfoRequest{})); err == nil {
			for s.Receive() {
				select {
				case changed <- struct{}{}:
				default:
				}
			}
			_ = s.Close()
		}
		select {
		case <-ctx.Done():
		case <-time.After(watchRetry):
		}
	}
}

// ResetSetupCode asks for a new setup code: it stops a browser setup that
// hasn't made the first admin, and ends a lockout.
func (a *AccessConsole) ResetSetupCode(ctx context.Context) error {
	_, err := a.Setup.ResetSetupCode(ctx, connect.NewRequest(&accessv1.ResetSetupCodeRequest{}))
	return err
}

// BeginRecoverAccess issues the console's Recover access code.
func (a *AccessConsole) BeginRecoverAccess(ctx context.Context) (RecoverCode, error) {
	r, err := a.Setup.BeginRecoverAccess(ctx, connect.NewRequest(&accessv1.BeginRecoverAccessRequest{}))
	if err != nil {
		return RecoverCode{}, err
	}
	return recoverFromWire(r.Msg.GetRecover()), nil
}

// CancelRecoverAccess withdraws the code.
func (a *AccessConsole) CancelRecoverAccess(ctx context.Context) error {
	_, err := a.Setup.CancelRecoverAccess(ctx, connect.NewRequest(&accessv1.CancelRecoverAccessRequest{}))
	return err
}

var states = map[accessv1.SetupState]SetupState{
	accessv1.SetupState_SETUP_STATE_IN_PROGRESS: SetupInProgress,
	accessv1.SetupState_SETUP_STATE_DONE:        SetupDone,
}

// stepNames are the :8443 setup steps as the console names them.
var stepNames = map[osadminv1.SetupStepKind]string{
	osadminv1.SetupStepKind_SETUP_STEP_KIND_CODE:          "The setup code",
	osadminv1.SetupStepKind_SETUP_STEP_KIND_ADMIN:         "Create the first admin",
	osadminv1.SetupStepKind_SETUP_STEP_KIND_RECOVERY_KEYS: "Recovery keys",
	osadminv1.SetupStepKind_SETUP_STEP_KIND_NETWORK:       "Network",
	osadminv1.SetupStepKind_SETUP_STEP_KIND_PROTECTION:    "Protection",
	osadminv1.SetupStepKind_SETUP_STEP_KIND_SIGN_IN:       "Sign in",
}

func at(ts interface{ AsTime() time.Time }, set bool) time.Time {
	if !set {
		return time.Time{}
	}
	return ts.AsTime()
}

func fromWire(m *accessv1.ConsoleInfo) ConsoleInfo {
	c := ConsoleInfo{
		State:           states[m.GetState()],
		SetupCode:       m.GetSetupCode(),
		CodeExpires:     at(m.GetCodeExpires(), m.GetCodeExpires() != nil),
		AttemptsLeft:    int(m.GetAttemptsLeft()),
		CodeLocked:      m.GetCodeLocked(),
		URL:             m.GetUrl(),
		URLs:            m.GetUrls(),
		FQDN:            m.GetFqdn(),
		CertFingerprint: m.GetCertFingerprint(),
		SetupSource:     m.GetSetupSource(),
		SetupStarted:    at(m.GetSetupStarted(), m.GetSetupStarted() != nil),
		SetupStep:       int(m.GetSetupStep()),
		SetupSteps:      int(m.GetSetupSteps()),
		StepName:        stepNames[m.GetSetupStepKind()],
		FirstAdmin:      m.GetFirstAdmin(),
		SSHOn:           m.GetSshOn(),
	}
	if r := m.GetRecover(); r != nil {
		rc := recoverFromWire(r)
		c.Recover = &rc
	}
	return c
}

func recoverFromWire(r *accessv1.RecoverAccess) RecoverCode {
	return RecoverCode{
		Code: r.GetCode(), Expires: at(r.GetExpires(), r.GetExpires() != nil), AttemptsLeft: int(r.GetAttemptsLeft()),
		URL: r.GetUrl(), InUse: r.GetInUse(), Source: r.GetSource(),
	}
}
