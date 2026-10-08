// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

// fakeSSHLogin is accessd's SshLoginService as the shell sees it.
type fakeSSHLogin struct {
	accessv1connect.UnimplementedSshLoginServiceHandler
	codes []string
	keys  []string
	ended []string
}

func (f *fakeSSHLogin) VerifyTotp(_ context.Context, r *connect.Request[accessv1.VerifyTotpRequest]) (*connect.Response[accessv1.VerifyTotpResponse], error) {
	f.codes = append(f.codes, r.Msg.GetTotpCode())
	f.keys = append(f.keys, r.Header().Get("Sneakers-Key-Fingerprint"))
	if r.Msg.GetTotpCode() != "123456" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("ACCESS_CREDENTIALS (3017): the authenticator code is wrong or was used already; 2 tries left"))
	}
	return connect.NewResponse(&accessv1.VerifyTotpResponse{Admin: "alice", LoginId: "L-1"}), nil
}

func (f *fakeSSHLogin) EndSshLogin(_ context.Context, r *connect.Request[accessv1.EndSshLoginRequest]) (*connect.Response[accessv1.EndSshLoginResponse], error) {
	f.ended = append(f.ended, r.Msg.GetLoginId())
	return connect.NewResponse(&accessv1.EndSshLoginResponse{}), nil
}

func withLogin(t *testing.T, f *fakeSSHLogin, fp string) *shell.Services {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(accessv1connect.NewSshLoginServiceHandler(f))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s := &shell.Services{Session: shell.Session{Admin: "alice", KeyFingerprint: fp, Source: "192.0.2.60"}}
	s.UseAccessd(http.DefaultClient, srv.URL)
	return s
}

// The login's first act is the TOTP check, with the key sshd authenticated;
// a refusal is the login's end.
func TestTheLoginChecksTheTOTPCodeFirst(t *testing.T) {
	f := &fakeSSHLogin{}
	s := withLogin(t, f, "SHA256:abc")
	id, err := s.VerifyTotp(context.Background(), "123456")
	if err != nil || id != "L-1" || f.keys[0] != "SHA256:abc" {
		t.Fatalf("%q %v %v", id, err, f.keys)
	}
	if _, err := s.VerifyTotp(context.Background(), "000000"); !codes.Is(err, codes.AccessCredentials) || !strings.Contains(err.Error(), "tries left") {
		t.Fatalf("a wrong code: %v", err)
	}
	s.EndLogin(context.Background(), id)
	if len(f.ended) != 1 || f.ended[0] != "L-1" {
		t.Fatalf("ended %v", f.ended)
	}
}

func TestALoginWithoutItsKeyIsRefused(t *testing.T) {
	f := &fakeSSHLogin{}
	s := withLogin(t, f, "")
	if _, err := s.VerifyTotp(context.Background(), "123456"); !codes.Is(err, codes.AccessForbidden) || len(f.codes) != 0 {
		t.Fatalf("%v %v", err, f.codes)
	}
}

func runWith(t *testing.T, b shell.Backend, line, stdin string) (string, string, error) {
	t.Helper()
	var out, errb strings.Builder
	e := &shell.Env{Origin: shell.OriginSSH, Backend: b, In: strings.NewReader(stdin), Out: &out, Err: &errb}
	err := shell.Run(context.Background(), e, line)
	return out.String(), errb.String(), err
}

func TestLaterSpecCommandsAreNotAvailable(t *testing.T) {
	s := &shell.Services{}
	for _, line := range []string{"tls show", "backup list", "restore", "upgrade status", "mcp off", "resources", "logs export", "support-bundle"} {
		_, stderr, err := runWith(t, s, line, "")
		if !codes.Is(err, codes.NotAvailable) || !strings.Contains(stderr, "Not available in this release") {
			t.Errorf("%q: %v %q", line, err, stderr)
		}
	}
}

func TestAccessdCommandsSayServicesUnavailable(t *testing.T) {
	s := &shell.Services{}
	for _, line := range []string{"status", "keys list", "admins list", "network show"} {
		_, stderr, err := runWith(t, s, line, "")
		if !codes.Is(err, codes.NotAvailable) || !strings.Contains(stderr, "appliance services are unavailable") {
			t.Errorf("%q: %v %q", line, err, stderr)
		}
	}
}

// fakePower is init's PowerService on power.sock as the shell sees it.
type fakePower struct {
	initv1connect.UnimplementedPowerServiceHandler
	calls  []string
	refuse error
}

func (f *fakePower) Reboot(_ context.Context, r *connect.Request[initv1.RebootRequest]) (*connect.Response[initv1.RebootResponse], error) {
	if f.refuse != nil {
		return nil, f.refuse
	}
	f.calls = append(f.calls, fmt.Sprintf("reboot forced=%v", r.Msg.GetForced()))
	return connect.NewResponse(&initv1.RebootResponse{}), nil
}

func (f *fakePower) PowerOff(_ context.Context, r *connect.Request[initv1.PowerOffRequest]) (*connect.Response[initv1.PowerOffResponse], error) {
	f.calls = append(f.calls, fmt.Sprintf("poweroff forced=%v", r.Msg.GetForced()))
	return connect.NewResponse(&initv1.PowerOffResponse{}), nil
}

func withPower(t *testing.T, f *fakePower) *shell.Services {
	t.Helper()
	_, h := initv1connect.NewPowerServiceHandler(f)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &shell.Services{Session: shell.Session{Admin: "alice"}, Power: initv1connect.NewPowerServiceClient(http.DefaultClient, srv.URL)}
}

func TestRebootAndPoweroffGoToInitGracefully(t *testing.T) {
	f := &fakePower{}
	s := withPower(t, f)
	if _, _, err := runWith(t, s, "reboot", "reboot\n"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runWith(t, s, "poweroff", "poweroff\n"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runWith(t, s, "reboot", "no\n"); err == nil {
		t.Fatal("an unconfirmed reboot went through")
	}
	if strings.Join(f.calls, ";") != "reboot forced=false;poweroff forced=false" {
		t.Fatalf("%v", f.calls)
	}
}

func TestInitsRefusalIsShown(t *testing.T) {
	s := withPower(t, &fakePower{refuse: connect.NewError(connect.CodePermissionDenied, errors.New("POWER_CALLER (3608): /tmp/x isn't osadmin or the closed shell"))})
	if _, _, err := runWith(t, s, "reboot", "reboot\n"); !codes.Is(err, codes.PowerCaller) {
		t.Fatalf("got %v", err)
	}
}
