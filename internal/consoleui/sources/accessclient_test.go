// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sources_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
)

// consoleSetup is accessd's SetupService console calls, from a scripted
// info.
type consoleSetup struct {
	accessv1connect.UnimplementedSetupServiceHandler
	mu      sync.Mutex
	info    *accessv1.ConsoleInfo
	updates chan *accessv1.ConsoleInfo
	calls   []string
}

func (s *consoleSetup) call(name string) {
	s.mu.Lock()
	s.calls = append(s.calls, name)
	s.mu.Unlock()
}

func (s *consoleSetup) GetConsoleInfo(context.Context, *connect.Request[accessv1.GetConsoleInfoRequest]) (*connect.Response[accessv1.GetConsoleInfoResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return connect.NewResponse(&accessv1.GetConsoleInfoResponse{ConsoleInfo: s.info}), nil
}

func (s *consoleSetup) WatchConsoleInfo(ctx context.Context, _ *connect.Request[accessv1.WatchConsoleInfoRequest], st *connect.ServerStream[accessv1.WatchConsoleInfoResponse]) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case i := <-s.updates:
			if err := st.Send(&accessv1.WatchConsoleInfoResponse{ConsoleInfo: i}); err != nil {
				return err
			}
		}
	}
}

func (s *consoleSetup) ResetSetupCode(context.Context, *connect.Request[accessv1.ResetSetupCodeRequest]) (*connect.Response[accessv1.ResetSetupCodeResponse], error) {
	s.call("reset")
	return connect.NewResponse(&accessv1.ResetSetupCodeResponse{}), nil
}

func (s *consoleSetup) BeginRecoverAccess(context.Context, *connect.Request[accessv1.BeginRecoverAccessRequest]) (*connect.Response[accessv1.BeginRecoverAccessResponse], error) {
	s.call("recover")
	return connect.NewResponse(&accessv1.BeginRecoverAccessResponse{Recover: &accessv1.RecoverAccess{Code: "6HDW-2RTE-KM8Q-0VXA", Url: "https://192.0.2.10:8443/recover", AttemptsLeft: 5}}), nil
}

func (s *consoleSetup) CancelRecoverAccess(context.Context, *connect.Request[accessv1.CancelRecoverAccessRequest]) (*connect.Response[accessv1.CancelRecoverAccessResponse], error) {
	s.call("cancel")
	return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("no code is out"))
}

func serveSetup(t *testing.T, s *consoleSetup) accessv1connect.SetupServiceClient {
	t.Helper()
	mux := http.NewServeMux()
	path, h := accessv1connect.NewSetupServiceHandler(s)
	mux.Handle(path, h)
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return accessv1connect.NewSetupServiceClient(srv.Client(), srv.URL)
}

// The console reads accessd's console info as the screens need it.
func TestAccessConsoleReadsTheInfo(t *testing.T) {
	expires := time.Date(2026, 10, 7, 15, 3, 0, 0, time.UTC)
	s := &consoleSetup{updates: make(chan *accessv1.ConsoleInfo), info: &accessv1.ConsoleInfo{
		State: accessv1.SetupState_SETUP_STATE_IN_PROGRESS, SetupCode: "7PQK-NMS9-XD2A-4KJW", CodeExpires: timestamppb.New(expires), AttemptsLeft: 4, CodeLocked: true,
		Url: "https://192.0.2.10:8443", Urls: []string{"https://192.0.2.10:8443"}, Fqdn: "sneakers.example.org",
		CertFingerprint: "7C2E91AB", SetupSource: "192.0.2.50", SetupStep: 2, SetupSteps: 6,
		SetupStepKind: osadminv1.SetupStepKind_SETUP_STEP_KIND_ADMIN, FirstAdmin: "alice", SshOn: true,
		Recover: &accessv1.RecoverAccess{Code: "6HDW-2RTE-KM8Q-0VXA", InUse: true, Source: "192.0.2.51"},
	}}
	a := &sources.AccessConsole{Setup: serveSetup(t, s)}
	c, err := a.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if c.State != sources.SetupInProgress || c.SetupCode != "7PQK-NMS9-XD2A-4KJW" || !c.CodeExpires.Equal(expires) || c.AttemptsLeft != 4 || !c.CodeLocked ||
		c.URL != "https://192.0.2.10:8443" || c.FQDN != "sneakers.example.org" || c.CertFingerprint != "7C2E91AB" ||
		c.SetupSource != "192.0.2.50" || c.SetupStep != 2 || c.SetupSteps != 6 || c.StepName != "Create the first admin" ||
		c.FirstAdmin != "alice" || !c.SSHOn || c.Recover == nil || !c.Recover.InUse || c.Recover.Source != "192.0.2.51" || !c.SetupStarted.IsZero() {
		t.Fatalf("%+v", c)
	}
}

// Every update accessd sends redraws the screen.
func TestAccessConsoleSignalsEachUpdate(t *testing.T) {
	s := &consoleSetup{updates: make(chan *accessv1.ConsoleInfo), info: &accessv1.ConsoleInfo{}}
	a := &sources.AccessConsole{Setup: serveSetup(t, s)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Watch(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	changed := a.Changed()
	for i := 0; i < 2; i++ {
		select {
		case s.updates <- &accessv1.ConsoleInfo{SetupCode: "4KJW-XD2A-7PQK-NMS9"}:
		case <-time.After(5 * time.Second):
			t.Fatal("nothing watched")
		}
		select {
		case <-changed:
		case <-time.After(5 * time.Second):
			t.Fatalf("update %d wasn't signalled", i)
		}
	}
}

// Reset, Recover access and its cancel reach accessd, and its refusals
// come back.
func TestAccessConsoleActions(t *testing.T) {
	s := &consoleSetup{updates: make(chan *accessv1.ConsoleInfo), info: &accessv1.ConsoleInfo{}}
	a := &sources.AccessConsole{Setup: serveSetup(t, s)}
	ctx := context.Background()
	if err := a.ResetSetupCode(ctx); err != nil {
		t.Fatal(err)
	}
	r, err := a.BeginRecoverAccess(ctx)
	if err != nil || r.Code != "6HDW-2RTE-KM8Q-0VXA" || r.URL != "https://192.0.2.10:8443/recover" || r.AttemptsLeft != 5 {
		t.Fatalf("%+v %v", r, err)
	}
	if err := a.CancelRecoverAccess(ctx); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("cancel: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) != 3 {
		t.Fatalf("calls %v", s.calls)
	}
}
