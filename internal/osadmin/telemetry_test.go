// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsecrets"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsettings"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

const telemetryProduct = `format: 2
telemetry:
  label: Traces and metrics
  restart:
    - sneakers/deployment/gateway
    - sneakers/deployment/mcp
    - sneakers/deployment/audit
    - sneakers/deployment/vault
box_settings:
  - configmap: sneakers/sneakers-telemetry
    keys:
      - {key: OTEL_EXPORTER_OTLP_ENDPOINT, setting: telemetry.endpoint}
      - {key: OTEL_EXPORTER_OTLP_CERTIFICATE, setting: telemetry.ca_file}
phases:
  - {name: identity, label: I, stack: s-identity, workloads: [vault]}
  - {name: services, label: S, stack: s-services, workloads: [audit]}
  - {name: front, label: F, stack: s-front, workloads: [gateway, mcp]}
`

// telemetryBox is a box whose product reads telemetry settings, with fakes
// for the cluster: mcp isn't there, and a workload in stuck never comes back.
type telemetryBox struct {
	*box
	alice    *browser
	mu       sync.Mutex
	restarts []string
	stuck    string
	probed   int
	probeErr error
	// lastProbe is the settings the last save's handshake was given.
	lastProbe boxsettings.Telemetry
}

func (e *telemetryBox) Applied(context.Context) error { return nil }

func (e *telemetryBox) Restart(_ context.Context, _, _, name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.restarts = append(e.restarts, name)
	return nil
}

func (e *telemetryBox) RolledOut(_ context.Context, _, _, name string) (string, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if name == "mcp" {
		return "", false, nil
	}
	if name == e.stuck {
		return "0 of 1 updated", true, nil
	}
	return "", true, nil
}

func (e *telemetryBox) restarted() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.restarts)
}

func newTelemetryBox(t *testing.T) *telemetryBox {
	t.Helper()
	return newTelemetryBoxWith(t, 200*time.Millisecond)
}

// newTelemetryBoxWith gives each phase bound to come back.
func newTelemetryBoxWith(t *testing.T, bound time.Duration) *telemetryBox {
	t.Helper()
	e := &telemetryBox{}
	b := newBox(t, true, func(b *box, o *osadmin.Options) {
		st := &boxsettings.Store{Dir: filepath.Join(b.state, "platform")}
		o.Telemetry = st
		o.Email = st
		o.BoxSecrets = &boxsecrets.Store{Dir: filepath.Join(b.state, "platform"), Manifests: filepath.Join(b.state, "k0s-manifests"), Settings: st}
		o.TelemetryWorkloads = e
		o.TelemetryPhaseBound = bound
		o.TelemetryPoll = 10 * time.Millisecond
		o.ProbeTelemetry = func(_ context.Context, tl boxsettings.Telemetry) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.probed++
			e.lastProbe = tl
			return e.probeErr
		}
	})
	e.box = b
	e.alice = b.browser()
	e.alice.signIn("alice")
	e.alice.installProduct(t, "0.2.0")
	if err := os.WriteFile(filepath.Join(b.state, "product", "current", productspec.File), []byte(telemetryProduct), 0o644); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *telemetryBox) client() osadminv1connect.TelemetryServiceClient {
	return osadminv1connect.NewTelemetryServiceClient(e.alice.hc, e.ts.URL)
}

// waitRestart waits for the restart to reach state.
func (e *telemetryBox) waitRestart(t *testing.T, state string) *osadminv1.TelemetryRestart {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		out, err := e.client().GetTelemetry(context.Background(), connect.NewRequest(&osadminv1.GetTelemetryRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		if r := out.Msg.GetRestart(); r.GetState() == state {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("the restart: %v, want %s", out.Msg.GetRestart(), state)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func set(endpoint string, enabled bool) *connect.Request[osadminv1.SetTelemetryRequest] {
	return connect.NewRequest(&osadminv1.SetTelemetryRequest{Settings: &osadminv1.TelemetrySettings{Enabled: enabled, Endpoint: endpoint}})
}

func TestTheServicesRestartPhaseByPhase(t *testing.T) {
	e := newTelemetryBox(t)
	e.alice.stepUp("alice")
	out, err := e.client().SetTelemetry(context.Background(), set("https://collector.example.com:4317", true))
	if err != nil || !out.Msg.GetRestarting() {
		t.Fatalf("%v, %v", out, err)
	}
	e.waitRestart(t, "done")
	if got := e.restarted(); !slices.Equal(got, []string{"vault", "audit", "gateway"}) {
		t.Fatalf("the order, with mcp left out: %v", got)
	}
	stack, err := os.ReadFile(filepath.Join(e.state, "k0s-manifests", productspec.BoxSecretsStack, productspec.BoxSecretsStack+".yaml"))
	if err != nil || !strings.Contains(string(stack), "https://collector.example.com:4317") {
		t.Fatalf("the stack: %v\n%s", err, stack)
	}
}

func TestAFailedPhaseStopsTheRestartAndARetryCarriesOn(t *testing.T) {
	e := newTelemetryBox(t)
	e.stuck = "audit"
	e.alice.stepUp("alice")
	if _, err := e.client().SetTelemetry(context.Background(), set("https://collector.example.com", true)); err != nil {
		t.Fatal(err)
	}
	r := e.waitRestart(t, "failed")
	if r.GetPhase() != "services" || !strings.Contains(r.GetWorkload(), "audit") || r.GetWhy() == "" {
		t.Fatalf("the failure: %v", r)
	}
	if got := e.restarted(); slices.Contains(got, "gateway") {
		t.Fatalf("a later phase restarted: %v", got)
	}
	e.mu.Lock()
	e.stuck = ""
	e.restarts = nil
	e.mu.Unlock()
	e.alice.stepUp("alice")
	if _, err := e.client().RetryTelemetryRestart(context.Background(), connect.NewRequest(&osadminv1.RetryTelemetryRestartRequest{})); err != nil {
		t.Fatal(err)
	}
	e.waitRestart(t, "done")
	if got := e.restarted(); !slices.Equal(got, []string{"audit", "gateway"}) {
		t.Fatalf("the retry: %v", got)
	}
}

func TestACollectorThatDoesntAnswerSavesNothing(t *testing.T) {
	e := newTelemetryBox(t)
	e.probeErr = errors.New("no")
	e.alice.stepUp("alice")
	if _, err := e.client().SetTelemetry(context.Background(), set("https://collector.example.com", true)); err == nil {
		t.Fatal("saved")
	}
	out, err := e.client().GetTelemetry(context.Background(), connect.NewRequest(&osadminv1.GetTelemetryRequest{}))
	if err != nil || out.Msg.GetState() != "off" || out.Msg.GetSettings().GetEndpoint() != "" {
		t.Fatalf("%v, %v", out, err)
	}
}

func TestAPlainEndpointIsRefused(t *testing.T) {
	e := newTelemetryBox(t)
	e.alice.stepUp("alice")
	_, err := e.client().SetTelemetry(context.Background(), set("http://collector.example.com", true))
	symbolIn(t, err, connect.CodeInvalidArgument, "TELEMETRY_INVALID")
}

func TestARetryWithNothingFailedIsRefused(t *testing.T) {
	e := newTelemetryBox(t)
	e.alice.stepUp("alice")
	_, err := e.client().RetryTelemetryRestart(context.Background(), connect.NewRequest(&osadminv1.RetryTelemetryRestartRequest{}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "TELEMETRY_RESTART")
}

// A restart may take a phase bound for k0s to apply the settings and one
// for each phase, so its maintenance holds that long, past the 15 minutes
// an apply holds, and then lapses: a restart that never ends doesn't block
// elevation for ever.
func TestAPhasedRestartHoldsMaintenanceForEveryPhase(t *testing.T) {
	e := newTelemetryBoxWith(t, 5*time.Minute)
	e.stuck = "audit"
	e.alice.stepUp("alice")
	if _, err := e.client().SetTelemetry(context.Background(), set("https://collector.example.com", true)); err != nil {
		t.Fatal(err)
	}
	// Three phases and the apply, 5 minutes each, and a minute's margin.
	want := 21 * time.Minute
	if want <= osadmin.MaintenanceBound {
		t.Fatalf("the test needs more than %s", osadmin.MaintenanceBound)
	}
	e.clk.Advance(osadmin.MaintenanceBound + time.Minute)
	if !e.srv.Maintenance() {
		t.Fatal("maintenance lapsed while the restart's phases still had time")
	}
	e.clk.Advance(want - osadmin.MaintenanceBound)
	if e.srv.Maintenance() {
		t.Fatal("a restart that never ends holds maintenance for ever")
	}
	e.mu.Lock()
	e.stuck = ""
	e.mu.Unlock()
	e.alice.signIn("alice")
	e.waitRestart(t, "done")
}

// The collector's CA is saved with the other settings, checked by the
// save's handshake, read back on the page, audited by fingerprint, and
// reaches the services as the CA file the exporters read.
func TestTheCollectorCAIsATelemetrySetting(t *testing.T) {
	e := newTelemetryBox(t)
	e.alice.stepUp("alice")
	ctx := context.Background()
	der, caPEM := testCollectorCA(t)
	req := connect.NewRequest(&osadminv1.SetTelemetryRequest{Settings: &osadminv1.TelemetrySettings{Enabled: true, Endpoint: "https://collector.example.com:4317", Logs: true, CaPem: caPEM}})
	if _, err := e.client().SetTelemetry(ctx, req); err != nil {
		t.Fatal(err)
	}
	e.waitRestart(t, "done")
	e.mu.Lock()
	probed := e.lastProbe
	e.mu.Unlock()
	if want := (boxsettings.Telemetry{Enabled: true, Endpoint: "https://collector.example.com:4317", Logs: true, CA: caPEM}); probed != want {
		t.Fatal("the save's handshake didn't get the CA")
	}
	got, err := e.client().GetTelemetry(ctx, connect.NewRequest(&osadminv1.GetTelemetryRequest{}))
	if err != nil || got.Msg.GetSettings().GetCaPem() != caPEM || got.Msg.GetLogsHeld() {
		t.Fatalf("the page reads %v, %v", got, err)
	}
	if a := lastEntry(t, e.log, "product.telemetry.set"); a.Outcome != "ok" || a.Detail["ca"] != osadmin.Fingerprint(der) || strings.Contains(a.Detail["ca"], "BEGIN") {
		t.Fatalf("audit %+v", a)
	}
	stack, err := os.ReadFile(filepath.Join(e.state, "k0s-manifests", productspec.BoxSecretsStack, productspec.BoxSecretsStack+".yaml"))
	if err != nil || !strings.Contains(string(stack), boxsettings.TelemetryCAFile) {
		t.Fatalf("the stack doesn't point the exporters at the CA: %v\n%s", err, stack)
	}
	bad := connect.NewRequest(&osadminv1.SetTelemetryRequest{Settings: &osadminv1.TelemetrySettings{Enabled: true, Endpoint: "https://collector.example.com:4317", CaPem: "not a certificate"}})
	_, err = e.client().SetTelemetry(ctx, bad)
	symbolIn(t, err, connect.CodeInvalidArgument, "TELEMETRY_INVALID")
}

// testCollectorCA is a self-signed CA: its DER and PEM.
func testCollectorCA(t *testing.T) ([]byte, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "collector test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
