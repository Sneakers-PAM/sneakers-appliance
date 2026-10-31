// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productswitch"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

// mcpBox is a box with a product whose mcp switch gates one stack and
// restarts the gateway, the probe p, and an admin who has stepped up.
func mcpBox(t *testing.T, p *fakeProbe, restart func(ns, kind, name string) error) (*box, osadminv1connect.McpServiceClient) {
	t.Helper()
	var sw *productswitch.Switches
	b := newBox(t, false, withProbe(p), func(b *box, o *osadmin.Options) {
		sw = &productswitch.Switches{Dir: filepath.Join(b.state, "platform"), Slot: filepath.Join(b.state, "product", "current"), Manifests: filepath.Join(b.state, "k0s-manifests"),
			Restart: func(_ context.Context, ns, kind, name string) error { return restart(ns, kind, name) }}
		o.Switches = sw
	})
	dir := filepath.Join(b.state, "product")
	installProduct(t, dir, mcpYAML)
	if err := os.MkdirAll(filepath.Join(dir, "a", "manifests", "sneakers-mcp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "manifests", "sneakers-mcp", "mcp.yaml"), []byte("kind: Deployment\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := productspec.WriteRBAC(filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sw.Manifests, 0o755); err != nil {
		t.Fatal(err)
	}
	alice := b.browser()
	alice.signIn("alice")
	alice.stepUp("alice")
	return b, osadminv1connect.NewMcpServiceClient(alice.hc, b.ts.URL)
}

func getMcp(t *testing.T, mc osadminv1connect.McpServiceClient) *osadminv1.GetMcpResponse {
	t.Helper()
	g, err := mc.GetMcp(context.Background(), connect.NewRequest(&osadminv1.GetMcpRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return g.Msg
}

func setMcp(mc osadminv1connect.McpServiceClient, on bool) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := mc.SetMcp(context.Background(), connect.NewRequest(&osadminv1.SetMcpRequest{McpEnabled: on, MachineApiEnabled: true}))
		done <- err
	}()
	return done
}

// Switching MCP on answers only once the product is ready with it: the
// MCP server and the workloads the switch restarts have rolled out and the
// product's health answers. Until then the page shows it starting, with
// what it waits for.
func TestTurningMCPOnAnswersOnceTheProductIsReady(t *testing.T) {
	p := &fakeProbe{step: productup.StepPods, detail: "Rolling out (13 of 14 ready): waiting for sneakers/sneakers-mcp, 0 of 1 updated, 1 running"}
	b, mc := mcpBox(t, p, func(string, string, string) error { return nil })
	done := setMcp(mc, true)
	deadline := time.Now().Add(5 * time.Second)
	for {
		g := getMcp(t, mc)
		if g.GetMcpEnabled() && g.GetReadiness() == "starting" {
			if g.GetState() != "on" || !strings.Contains(g.GetDetail(), "sneakers/sneakers-mcp") {
				t.Fatalf("while starting: %v", g)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never shown starting: %v", g)
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("SetMcp answered %v before the product was ready", err)
	case <-time.After(50 * time.Millisecond):
	}
	p.set("", "", nil)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if g := getMcp(t, mc); g.GetReadiness() != "ready" || g.GetDetail() != "" {
		t.Fatalf("after: %v", g)
	}
	if e := lastEntry(t, b.log, "mcp.set"); e.Outcome != "ok" {
		t.Fatalf("audit %+v", e)
	}
}

// When the product isn't ready with MCP on within the bound, SetMcp fails
// with what it waits for, the audit says so, and the page shows it failed:
// the switch stays on, and the card shows the reason instead of "On".
func TestTurningMCPOnFailsWhenTheProductIsntReadyInTime(t *testing.T) {
	p := &fakeProbe{step: productup.StepPods, detail: "Rolling out (13 of 14 ready): waiting for sneakers/sneakers-mcp, 0 of 1 updated, 1 running"}
	b, mc := mcpBox(t, p, func(string, string, string) error { return nil })
	done := setMcp(mc, true)
	var err error
	for got := false; !got; {
		b.clk.Advance(osadmin.DefaultSwitchReadyBound + time.Second)
		select {
		case err = <-done:
			got = true
		case <-time.After(20 * time.Millisecond):
		}
	}
	symbolIn(t, err, connect.CodeFailedPrecondition, "PRODUCT_NOT_READY")
	if !strings.Contains(err.Error(), "sneakers/sneakers-mcp") {
		t.Fatalf("error %v doesn't say what it waits for", err)
	}
	if e := lastEntry(t, b.log, "mcp.set"); e.Outcome == "ok" {
		t.Fatalf("audit %+v", e)
	}
	g := getMcp(t, mc)
	if !g.GetMcpEnabled() || g.GetReadiness() != "failed" || !strings.Contains(g.GetDetail(), "sneakers/sneakers-mcp") {
		t.Fatalf("after: %v", g)
	}
	p.set("", "", nil)
	if g := getMcp(t, mc); g.GetReadiness() != "ready" {
		t.Fatalf("once ready: %v", g)
	}
}

// A restart the switch needs that doesn't go through fails the set: the
// workloads that read the switch would keep the old setting.
func TestASwitchRestartThatFailsFailsTheSet(t *testing.T) {
	_, mc := mcpBox(t, &fakeProbe{}, func(string, string, string) error {
		return errors.New("rollout restart: deployments.apps \"sneakers-gateway\" not found")
	})
	err := <-setMcp(mc, true)
	if err == nil || !strings.Contains(err.Error(), "sneakers-gateway") {
		t.Fatalf("SetMcp = %v", err)
	}
}

// mcpEntries are the box's mcp.set audit entries, oldest first.
func mcpEntries(t *testing.T, b *box) []osaudit.Entry {
	t.Helper()
	es, err := b.log.Entries()
	if err != nil {
		t.Fatal(err)
	}
	var out []osaudit.Entry
	for _, e := range es {
		if e.Action == "mcp.set" {
			out = append(out, e)
		}
	}
	return out
}

// answered waits until the request behind done has answered, ok.
func answered(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the request never answered")
	}
}

// heldRestart is a switch restart that waits to be let go, and counts how
// many run at once.
type heldRestart struct {
	mu      sync.Mutex
	running int
	most    int
	calls   int
	entered chan struct{}
	release chan struct{}
	freed   sync.Once
}

func newHeldRestart(t *testing.T) *heldRestart {
	h := &heldRestart{entered: make(chan struct{}, 8), release: make(chan struct{})}
	t.Cleanup(h.free)
	return h
}

func (h *heldRestart) free() { h.freed.Do(func() { close(h.release) }) }

func (h *heldRestart) restart(string, string, string) error {
	h.mu.Lock()
	h.calls++
	h.running++
	h.most = max(h.most, h.running)
	h.mu.Unlock()
	h.entered <- struct{}{}
	<-h.release
	h.mu.Lock()
	h.running--
	h.mu.Unlock()
	return nil
}

func (h *heldRestart) counts() (calls, most int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls, h.most
}

// On, off and on within a second collapse to the last one. The first is
// applied, nothing runs beside it, the off it replaced is never applied,
// each request has its own audit entry, and MCP ends on and ready.
func TestRapidMCPTogglesCollapseToTheLastRequest(t *testing.T) {
	h := newHeldRestart(t)
	p := &fakeProbe{}
	b, mc := mcpBox(t, p, h.restart)
	first := setMcp(mc, true)
	<-h.entered
	second := setMcp(mc, false)
	waitForMcpState(t, mc, "off")
	third := setMcp(mc, true)
	answered(t, second)
	g := getMcp(t, mc)
	if !g.GetMcpEnabled() || g.GetReadiness() != "starting" {
		t.Fatalf("with the switch still being applied: %v", g)
	}
	h.free()
	answered(t, first)
	answered(t, third)
	calls, most := h.counts()
	if most != 1 || calls != 1 {
		t.Fatalf("%d applies, %d at once", calls, most)
	}
	if g := getMcp(t, mc); !g.GetMcpEnabled() || g.GetState() != "on" || g.GetReadiness() != "ready" {
		t.Fatalf("after: %v", g)
	}
	if _, err := os.Stat(filepath.Join(b.state, "k0s-manifests", "sneakers-mcp", "mcp.yaml")); err != nil {
		t.Fatal(err)
	}
	got := mcpEntries(t, b)
	if len(got) != 3 {
		t.Fatalf("audit %+v", got)
	}
	for _, e := range got {
		if e.Outcome != "ok" {
			t.Fatalf("audit %+v", got)
		}
	}
}

func waitForMcpState(t *testing.T, mc osadminv1connect.McpServiceClient, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		g := getMcp(t, mc)
		if g.GetState() == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("never %s: %v", want, g)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// A last request that differs from the one in flight runs once that one
// is done, and the stack it leaves is the one it asked for.
func TestAnOffBehindAnOnInFlightRunsAfterIt(t *testing.T) {
	h := newHeldRestart(t)
	b, mc := mcpBox(t, &fakeProbe{}, h.restart)
	first := setMcp(mc, true)
	<-h.entered
	second := setMcp(mc, false)
	waitForMcpState(t, mc, "off")
	if calls, _ := h.counts(); calls != 1 {
		t.Fatalf("the off ran beside the on: %d", calls)
	}
	h.free()
	answered(t, first)
	answered(t, second)
	if calls, most := h.counts(); calls != 2 || most != 1 {
		t.Fatalf("%d applies, %d at once", calls, most)
	}
	if _, err := os.Stat(filepath.Join(b.state, "k0s-manifests", "sneakers-mcp")); !os.IsNotExist(err) {
		t.Fatalf("the stack is still there: %v", err)
	}
	if g := getMcp(t, mc); g.GetMcpEnabled() || g.GetState() != "off" || g.GetReadiness() != "" {
		t.Fatalf("after: %v", g)
	}
}

// A request doesn't sit behind the readiness wait of the one before it: it
// has been told to change, so the wait ends and the change runs.
func TestARequestEndsTheWaitOfTheOneBefore(t *testing.T) {
	p := &fakeProbe{step: productup.StepPods, detail: "Rolling out: waiting for sneakers/sneakers-mcp"}
	b, mc := mcpBox(t, p, func(string, string, string) error { return nil })
	first := setMcp(mc, true)
	waitForMcpState(t, mc, "on")
	second := setMcp(mc, false)
	p.set("", "", nil)
	answered(t, first)
	answered(t, second)
	if g := getMcp(t, mc); g.GetState() != "off" {
		t.Fatalf("after: %v", g)
	}
	if got := mcpEntries(t, b); len(got) != 2 || got[0].Outcome != "ok" || got[1].Outcome != "ok" {
		t.Fatalf("audit %+v", got)
	}
}

// With MCP off the page names no readiness.
func TestMCPOffHasNoReadiness(t *testing.T) {
	_, mc := mcpBox(t, &fakeProbe{step: productup.StepPods, detail: "x"}, func(string, string, string) error { return nil })
	if g := getMcp(t, mc); g.GetState() != "off" || g.GetReadiness() != "" || g.GetDetail() != "" {
		t.Fatalf("%v", g)
	}
}
