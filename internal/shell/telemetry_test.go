// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1/accessv1connect"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

type telemetryAccessd struct {
	fakeAccessd
	state   *osadminv1.GetTelemetryResponse
	sets    []*accessv1.SetTelemetryRequest
	retries int
}

func (f *telemetryAccessd) GetTelemetry(_ context.Context, r *connect.Request[accessv1.GetTelemetryRequest]) (*connect.Response[accessv1.GetTelemetryResponse], error) {
	f.saw(r.Header())
	return connect.NewResponse(&accessv1.GetTelemetryResponse{Telemetry: f.state}), nil
}

func (f *telemetryAccessd) SetTelemetry(_ context.Context, r *connect.Request[accessv1.SetTelemetryRequest]) (*connect.Response[accessv1.SetTelemetryResponse], error) {
	f.saw(r.Header())
	f.sets = append(f.sets, r.Msg)
	f.state.Settings = r.Msg.GetSettings()
	return connect.NewResponse(&accessv1.SetTelemetryResponse{Restarting: true}), nil
}

func (f *telemetryAccessd) RetryTelemetryRestart(_ context.Context, r *connect.Request[accessv1.RetryTelemetryRestartRequest]) (*connect.Response[accessv1.RetryTelemetryRestartResponse], error) {
	f.saw(r.Header())
	f.retries++
	return connect.NewResponse(&accessv1.RetryTelemetryRestartResponse{}), nil
}

func runTelemetry(t *testing.T, f *telemetryAccessd, line string) (string, error) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(accessv1connect.NewAccessServiceHandler(f))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	s := &shell.Services{Session: shell.Session{Admin: "alice", KeyFingerprint: "SHA256:abc", Source: "192.0.2.60"}}
	s.UseAccessd(http.DefaultClient, srv.URL)
	var out, errb bytes.Buffer
	e := &shell.Env{Origin: shell.OriginSSH, Backend: s, In: strings.NewReader(""), Out: &out, Err: &errb, Product: sneakers}
	err := shell.Run(context.Background(), e, line)
	return out.String() + errb.String(), err
}

func TestTheShellsTelemetryCommandDrivesTheSettings(t *testing.T) {
	f := &telemetryAccessd{state: &osadminv1.GetTelemetryResponse{State: "off", Settings: &osadminv1.TelemetrySettings{Endpoint: "https://old.example.com", Logs: true},
		Restart:   &osadminv1.TelemetryRestart{State: "failed", Phase: "services", Workload: "sneakers/deployment/sneakers-audit", Why: "it isn't back"},
		Workloads: []*osadminv1.TelemetryWorkload{{Name: "vault", State: "sending"}}}}
	out, err := runTelemetry(t, f, "sneakers telemetry")
	for _, want := range []string{"off", "https://old.example.com", "failed", "sneakers-audit", "vault", "sending"} {
		if err != nil || !strings.Contains(out, want) {
			t.Fatalf("no %q: %v\n%s", want, err, out)
		}
	}
	if _, err = runTelemetry(t, f, "sneakers telemetry on https://new.example.com:4317 verify=off"); err != nil {
		t.Fatal(err)
	}
	s := f.sets[0].GetSettings()
	if !s.GetEnabled() || s.GetEndpoint() != "https://new.example.com:4317" || !s.GetSkipVerify() || !s.GetLogs() {
		t.Fatalf("on: %v", s)
	}
	if _, err = runTelemetry(t, f, "sneakers telemetry off"); err != nil {
		t.Fatal(err)
	}
	if s := f.sets[1].GetSettings(); s.GetEnabled() || s.GetEndpoint() != "https://new.example.com:4317" {
		t.Fatalf("off lost the endpoint: %v", s)
	}
	if _, err = runTelemetry(t, f, "sneakers telemetry on logs=off"); err != nil {
		t.Fatal(err)
	}
	if s := f.sets[2].GetSettings(); !s.GetEnabled() || s.GetLogs() || s.GetEndpoint() != "https://new.example.com:4317" {
		t.Fatalf("on with the saved endpoint: %v", s)
	}
	if _, err = runTelemetry(t, f, "sneakers telemetry retry"); err != nil || f.retries != 1 {
		t.Fatalf("retry: %v, %d", err, f.retries)
	}
	for _, line := range []string{"sneakers telemetry maybe", "sneakers telemetry on logs=perhaps", "sneakers telemetry on colour=blue", "sneakers telemetry off https://x.example.com"} {
		_, err := runTelemetry(t, f, line)
		assertCode(t, err, "SHELL_PARSE")
	}
	if len(f.sets) != 3 {
		t.Fatalf("a bad line set something: %v", f.sets)
	}
}
