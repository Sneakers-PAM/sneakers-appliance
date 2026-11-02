// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

package k0s_test

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestTheRealBundleRestartsForTelemetryInOrder points the real product at a
// collector over SSH: the services restart in the order of the phases, each
// phase only once the one before is back, and the box goes on running.
func TestTheRealBundleRestartsForTelemetryInOrder(t *testing.T) {
	e := needReal(t)
	image := os.Getenv("SNEAKERS_REAL_NEW_IMAGE")
	if image == "" {
		t.Skip("SNEAKERS_REAL_NEW_IMAGE names the base under test")
	}
	b := newRealBoxFrom(t, e, image, e.newVersion, 0)
	v := productVersion(e.next)
	b.apply(e.next, "UPDATE_TARGET_PRODUCT")
	base := b.mustRun(v, "the install of "+v, realRows{}, true, false).rows

	// The box answers a save only after a TLS handshake with the collector;
	// QEMU's user network reaches the host.
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.NewServeMux())
	srv.Listener = l
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	port := l.Addr().(*net.TCPAddr).Port

	out, err := ssh(b.ctx, b.sshPort, b.alice, "sneakers", "telemetry", "on", fmt.Sprintf("https://10.0.2.2:%d", port), "verify=off")
	if err != nil || !strings.Contains(out, "restart phase by phase") {
		t.Fatalf("telemetry on: %v\n%s", err, out)
	}
	t.Logf("telemetry on: %s", strings.TrimSpace(out))
	b.vm.Expect(`realci: telemetry restart=done`, 20*time.Minute)
	b.vm.Expect(`realci: pods telemetry version=`, time.Minute)
	pods, err := readRealPods(lastLine(b.vm.Console(), "realci: pods telemetry version="))
	if err != nil {
		t.Fatal(err)
	}
	last := time.Time{}
	for _, phase := range [][]string{{"sneakers-identity", "sneakers-vault"}, {"sneakers-workflow", "sneakers-audit", "sneakers-notify", "sneakers-connector", "sneakers-sshbroker"}, {"sneakers-gateway"}} {
		var first, end time.Time
		for _, p := range pods {
			for _, app := range phase {
				if p.app != app || !p.ready {
					continue
				}
				if first.IsZero() || p.started.Before(first) {
					first = p.started
				}
				if p.readyAt.After(end) {
					end = p.readyAt
				}
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
	if p := rowProblems(base, b.mustRun(v, "after the restart", base, true, false).rows); len(p) > 0 {
		t.Fatalf("after the restart: %v", p)
	}
}
