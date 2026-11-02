// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxsettings_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsettings"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

func TestTelemetryIsOffByDefault(t *testing.T) {
	st := boxsettings.Store{Dir: t.TempDir()}
	got, err := st.Telemetry()
	if err != nil {
		t.Fatal(err)
	}
	if got != (boxsettings.Telemetry{}) {
		t.Fatalf("the default: %+v", got)
	}
	v, err := st.Values()
	if err != nil {
		t.Fatal(err)
	}
	if v[productspec.SettingTelemetryEndpoint] != "" || v[productspec.SettingTelemetrySkipVerify] != "false" || v[productspec.SettingTelemetryLogs] != "false" {
		t.Fatalf("the default values: %v", v)
	}
	if _, ok := v[productspec.SettingEmailHost]; !ok {
		t.Fatalf("the email settings went missing: %v", v)
	}
}

func TestTheTelemetrySettingsAreKeptBesideTheRelay(t *testing.T) {
	st := boxsettings.Store{Dir: t.TempDir()}
	e := boxsettings.DefaultEmail()
	e.Host, e.From = "relay.example.com", "box@example.com"
	if err := st.SetEmail(e); err != nil {
		t.Fatal(err)
	}
	want := boxsettings.Telemetry{Enabled: true, Endpoint: "https://collector.example.com:4317", Logs: true}
	if err := st.SetTelemetry(want); err != nil {
		t.Fatal(err)
	}
	got, err := st.Telemetry()
	if err != nil || got != want {
		t.Fatalf("saved %+v, read %+v, %v", want, got, err)
	}
	if kept, err := st.Email(); err != nil || kept.Host != e.Host {
		t.Fatalf("the relay after a telemetry save: %+v, %v", kept, err)
	}
}

func TestOffStopsTheExportAndKeepsTheEndpoint(t *testing.T) {
	st := boxsettings.Store{Dir: t.TempDir()}
	saved := boxsettings.Telemetry{Endpoint: "https://collector.example.com:4317", Logs: true}
	if err := st.SetTelemetry(saved); err != nil {
		t.Fatal(err)
	}
	if got, err := st.Telemetry(); err != nil || got.Endpoint != saved.Endpoint {
		t.Fatalf("the endpoint wasn't kept: %+v, %v", got, err)
	}
	v := saved.Values()
	if v[productspec.SettingTelemetryEndpoint] != "" || v[productspec.SettingTelemetryLogs] != "false" {
		t.Fatalf("off still exports: %v", v)
	}
}

func TestNoLogsLeaveWhileTheCollectorIsntVerified(t *testing.T) {
	v := boxsettings.Telemetry{Enabled: true, Endpoint: "https://collector.example.com", SkipVerify: true, Logs: true}.Values()
	if v[productspec.SettingTelemetryLogs] != "false" {
		t.Fatalf("logs go to a collector that isn't verified: %v", v)
	}
	if v[productspec.SettingTelemetryEndpoint] == "" || v[productspec.SettingTelemetrySkipVerify] != "true" {
		t.Fatalf("traces and metrics should keep flowing: %v", v)
	}
}

func TestTheEndpointMustBeHTTPS(t *testing.T) {
	for _, bad := range []string{
		"http://collector.example.com:4317",
		"collector.example.com:4317",
		"grpc://collector.example.com:4317",
		"https://",
		"https://:4317",
		"https://collector.example.com:0",
		"https://collector.example.com:70000",
		"https://user:pass@collector.example.com",
		"https://collector.example.com/v1/traces",
		"https://collector.example.com?x=1",
		"https://collector.example.com#x",
		"https://bad host.example.com",
		" https://collector.example.com",
	} {
		if err := (boxsettings.Telemetry{Enabled: true, Endpoint: bad}).Check(); err == nil {
			t.Errorf("%q was taken", bad)
		}
		if err := (boxsettings.Telemetry{Endpoint: bad}).Check(); err == nil {
			t.Errorf("%q was taken while off", bad)
		}
	}
	for _, good := range []string{"https://collector.example.com", "https://collector.example.com:4317", "https://192.0.2.10:4317", "https://[2001:db8::1]:4317"} {
		if err := (boxsettings.Telemetry{Enabled: true, Endpoint: good}).Check(); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	if err := (boxsettings.Telemetry{Enabled: true}).Check(); err == nil {
		t.Error("on with no endpoint was taken")
	}
	if err := (boxsettings.Telemetry{}).Check(); err != nil {
		t.Errorf("off with no endpoint: %v", err)
	}
	st := boxsettings.Store{Dir: t.TempDir()}
	if err := st.SetTelemetry(boxsettings.Telemetry{Enabled: true, Endpoint: "http://collector.example.com"}); err == nil {
		t.Error("SetTelemetry saved a plain http endpoint")
	}
}
