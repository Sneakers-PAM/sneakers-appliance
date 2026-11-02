// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

package k0s_test

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

// telemetryPhases are the Sneakers product's phases a telemetry restart
// runs, in order, with the workloads that read the settings.
var telemetryPhases = [][]string{
	{"sneakers-identity", "sneakers-vault"},
	{"sneakers-workflow", "sneakers-audit", "sneakers-notify", "sneakers-connector", "sneakers-sshbroker"},
	{"sneakers-gateway"},
}

// TestTheRealBundleRestartsForTelemetryInOrder points the real product at
// a collector from the :8443 Telemetry page, the only place it's set:
//
//   - stop on failure: the lab hook keeps sneakers-notify from coming back
//     (the "telemetry-break" marker), so the services phase runs out of
//     time; the page says where it stopped, the gateway's phase never
//     restarted, and the product goes on running. The hook then frees it,
//     and a retry carries on from that phase;
//   - order: each phase's workloads restart only once the phase before is
//     back;
//   - canary: values that must never leave the box (the product's setup
//     token, and made-up ones sent in a header, a query string and a body)
//     are pushed through the gateway while the services export, and the
//     collector has to have received traces or metrics, and none of them.
//     No logs leave: the collector isn't verified.
func TestTheRealBundleRestartsForTelemetryInOrder(t *testing.T) {
	e := needReal(t)
	image := os.Getenv("SNEAKERS_REAL_NEW_IMAGE")
	if image == "" {
		t.Skip("SNEAKERS_REAL_NEW_IMAGE names the base under test")
	}
	harness.Need(t, []string{"socat"})
	// QEMU's user network gives the box no way out (restrict=on) but its
	// guestfwd rules, so the collector listens on the runner before the box
	// boots, at podEgressTarget on the box's side. socat makes one
	// connection per connect: the save's handshake and each service's.
	col := newCanaryCollector(t)
	fwd := fmt.Sprintf("tcp:%s-cmd:socat - TCP:127.0.0.1:%d", podEgressTarget, col.port)
	b := newRealBoxMarked(t, e, image, e.newVersion, 0, "telemetry-break\n", []string{fwd})
	v := productVersion(e.next)
	b.apply(e.next, "UPDATE_TARGET_PRODUCT")
	installed := b.mustRun(v, "the install of "+v, realRows{}, true, false)

	// The box answers a save only after a TLS handshake with the
	// collector. The endpoint's port is the one the box opens in the MCP
	// server's NetworkPolicy.
	adm := signIn(t, b.adminPort, b.alice)
	adm.call(t, "SignInService/StepUp", map[string]any{"totpCode": b.alice.code()}, &struct{}{})
	var set struct {
		Restarting bool `json:"restarting"`
	}
	adm.call(t, "TelemetryService/SetTelemetry", map[string]any{"settings": map[string]any{
		"enabled": true, "endpoint": "https://" + podEgressTarget.String(), "skipVerify": true, "logs": true,
	}}, &set)
	if !set.Restarting {
		t.Fatal("the save didn't restart the services")
	}

	// Stop on failure.
	b.vm.Expect(`realci: telemetry break=on`, 10*time.Minute)
	b.vm.Expect(`realci: telemetry restart=failed`, 20*time.Minute)
	b.vm.Expect(`realci: telemetry break=off`, time.Minute)
	got := telemetryState(t, signIn(t, b.adminPort, b.alice))
	if r := got.Restart; r.State != "failed" || r.Phase != "services" || !strings.Contains(r.Workload, "sneakers-notify") || r.Why == "" {
		t.Fatalf("the failed restart, as the page shows it: %+v", r)
	}
	if !got.LogsHeld {
		t.Fatal("logs are on with an unverified collector, and the page doesn't say they stay on the box")
	}
	b.vm.Expect(`realci: pods telemetry version=`, time.Minute)
	stopped, err := readRealPods(lastLine(b.vm.Console(), "realci: pods telemetry version="))
	if err != nil {
		t.Fatal(err)
	}
	if before, after := readyPodNames(installed.pods, "sneakers-gateway"), readyPodNames(stopped, "sneakers-gateway"); len(before) == 0 || !slices.Equal(before, after) {
		t.Fatalf("the gateway's phase came after the one that failed, but its pods changed: %v, then %v", before, after)
	}
	t.Logf("the restart stopped at %s (%s): %s", got.Restart.Phase, got.Restart.Workload, got.Restart.Why)

	// The retry, from the phase that failed.
	adm = signIn(t, b.adminPort, b.alice)
	adm.call(t, "SignInService/StepUp", map[string]any{"totpCode": b.alice.code()}, &struct{}{})
	adm.call(t, "TelemetryService/RetryTelemetryRestart", map[string]any{}, &struct{}{})
	b.vm.Expect(`realci: telemetry restart=done`, 20*time.Minute)
	b.vm.Expect(`realci: pods telemetry version=`, time.Minute)
	pods, err := readRealPods(lastLine(b.vm.Console(), "realci: pods telemetry version="))
	if err != nil {
		t.Fatal(err)
	}

	// The order.
	last := time.Time{}
	for _, phase := range telemetryPhases {
		var first, end time.Time
		for _, p := range pods {
			if !p.ready || !slices.Contains(phase, p.app) {
				continue
			}
			if first.IsZero() || p.started.Before(first) {
				first = p.started
			}
			if p.readyAt.After(end) {
				end = p.readyAt
			}
		}
		if first.IsZero() {
			t.Fatalf("no pod of %v is ready: %+v", phase, pods)
		}
		if first.Before(last) {
			t.Fatalf("%v started at %s, before the phase before was ready at %s", phase, first, last)
		}
		last = end
	}
	if r := telemetryState(t, signIn(t, b.adminPort, b.alice)).Restart; r.State != "done" {
		t.Fatalf("after the retry the page shows %+v", r)
	}
	if p := rowProblems(installed.rows, b.mustRun(v, "after the restart", installed.rows, true, false).rows); len(p) > 0 {
		t.Fatalf("after the restart: %v", p)
	}

	// The canary.
	canaries := map[string]string{"the setup token": setupToken(b.ctx, t, b.sshPort, b.alice)}
	for _, where := range []string{"a bearer token", "a query string", "a request body"} {
		canaries[where] = "realci-canary-" + randomHex(t)
	}
	sendCanaries(t, b.hp, canaries)
	col.waitForExports(t, 5*time.Minute)
	// One more metrics interval, so what the requests made is flushed too.
	time.Sleep(70 * time.Second)
	sendCanaries(t, b.hp, canaries)
	time.Sleep(70 * time.Second)
	paths, size := col.summary()
	t.Logf("the collector received %d bytes: %v", size, paths)
	for where, value := range canaries {
		if col.saw(value) {
			t.Errorf("the collector received %s", where)
		}
	}
	for p := range paths {
		if strings.Contains(p, "LogsService") {
			t.Errorf("logs reached a collector that isn't verified: %s", p)
		}
	}
}

// telemetryPage is what the Telemetry page reads.
type telemetryPage struct {
	State    string `json:"state"`
	LogsHeld bool   `json:"logsHeld"`
	Restart  struct {
		State    string `json:"state"`
		Phase    string `json:"phase"`
		Workload string `json:"workload"`
		Why      string `json:"why"`
	} `json:"restart"`
}

func telemetryState(t *testing.T, adm *admin) telemetryPage {
	t.Helper()
	var out telemetryPage
	adm.call(t, "TelemetryService/GetTelemetry", map[string]any{}, &out)
	return out
}

// readyPodNames are app's ready pods, by name, sorted.
func readyPodNames(pods []realPod, app string) []string {
	var out []string
	for _, p := range pods {
		if p.app == app && p.ready {
			out = append(out, p.name)
		}
	}
	slices.Sort(out)
	return out
}

func randomHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// sendCanaries sends the canaries through the box's edge to the gateway,
// where its tracing and logging see them: as a bearer token, in a query
// string and in a body. The answers don't matter.
func sendCanaries(t *testing.T, port int, canaries map[string]string) {
	t.Helper()
	c := http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- the box's self-signed certificate
	}}
	base := fmt.Sprintf("https://127.0.0.1:%d", port)
	send := func(method, path, auth string, body []byte) {
		req, err := http.NewRequest(method, base+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Logf("%s %s: %v", method, path, err)
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		t.Logf("%s %s: %s", method, strings.SplitN(path, "?", 2)[0], resp.Status)
	}
	token := canaries["the setup token"]
	send(http.MethodGet, "/setup/state", canaries["a bearer token"], nil)
	send(http.MethodGet, "/admin/setup?token="+canaries["a query string"], "", nil)
	send(http.MethodPost, "/admin/setup", "", fmt.Appendf(nil, `{"token":%q,"password":%q}`, token, canaries["a request body"]))
	send(http.MethodGet, "/admin/setup?token="+token, token, nil)
}

// canaryCollector is an OTLP/gRPC collector on the host that keeps every
// message it's sent, gzip or not, and answers each with an empty one.
type canaryCollector struct {
	port  int
	mu    sync.Mutex
	got   []byte
	paths map[string]int
	first chan struct{}
	once  sync.Once
}

func newCanaryCollector(t *testing.T) *canaryCollector {
	t.Helper()
	c := &canaryCollector{paths: map[string]int{}, first: make(chan struct{})}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(c.serve))
	srv.Listener = l
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	c.port = l.Addr().(*net.TCPAddr).Port
	return c
}

func (c *canaryCollector) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var msgs [][]byte
	for len(body) >= 5 {
		n := int(binary.BigEndian.Uint32(body[1:5]))
		if len(body) < 5+n {
			break
		}
		m := body[5 : 5+n]
		if body[0] == 1 {
			if zr, err := gzip.NewReader(bytes.NewReader(m)); err == nil {
				if plain, err := io.ReadAll(zr); err == nil {
					m = plain
				}
			}
		}
		msgs = append(msgs, m)
		body = body[5+n:]
	}
	c.mu.Lock()
	c.paths[r.URL.Path]++
	for _, m := range msgs {
		c.got = append(c.got, m...)
		c.got = append(c.got, 0)
	}
	c.mu.Unlock()
	if len(msgs) > 0 {
		c.once.Do(func() { close(c.first) })
	}
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Trailer", "Grpc-Status")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte{0, 0, 0, 0, 0})
	w.Header().Set("Grpc-Status", "0")
}

// waitForExports fails unless a service exports within max: without any,
// the canary proves nothing.
func (c *canaryCollector) waitForExports(t *testing.T, max time.Duration) {
	t.Helper()
	select {
	case <-c.first:
	case <-time.After(max):
		t.Fatalf("no service exported to the collector in %s", max)
	}
}

func (c *canaryCollector) saw(value string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Contains(c.got, []byte(value))
}

func (c *canaryCollector) summary() (map[string]int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	paths := map[string]int{}
	for p, n := range c.paths {
		paths[p] = n
	}
	return paths, len(c.got)
}
