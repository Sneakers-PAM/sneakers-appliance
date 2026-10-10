// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

func (b *box) finishSetup() {
	b.t.Helper()
	if err := os.MkdirAll(filepath.Join(b.state, "setup"), 0o700); err != nil {
		b.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.state, "setup", osadmin.DoneMarker), nil, 0o600); err != nil {
		b.t.Fatal(err)
	}
	b.done = true
}

// Anyone may ask the phase: the pages read it before a session exists.
func TestThePhaseIsPublic(t *testing.T) {
	b := newBox(t, false)
	st := osadminv1connect.NewStatusServiceClient(b.browser().hc, b.ts.URL)
	ctx := context.Background()
	p, err := st.GetPhase(ctx, connect.NewRequest(&osadminv1.GetPhaseRequest{}))
	if err != nil || p.Msg.GetPhase() != osadmin.PhaseFirstBoot {
		t.Fatalf("before setup: %v %v", p, err)
	}
	b.finishSetup()
	p, err = st.GetPhase(ctx, connect.NewRequest(&osadminv1.GetPhaseRequest{}))
	if err != nil || p.Msg.GetPhase() != osadmin.PhaseNormal {
		t.Fatalf("after setup: %v %v", p, err)
	}
}

var pageAssets = fstest.MapFS{
	"index.html":       &fstest.MapFile{Data: []byte("<html>admin</html>")},
	"assets/app.js":    &fstest.MapFile{Data: []byte("console.log(1)")},
	"assets/app.css":   &fstest.MapFile{Data: []byte("body{}")},
	"favicon.svg":      &fstest.MapFile{Data: []byte("<svg/>")},
	"assets/fonts/a.w": &fstest.MapFile{Data: []byte("w")},
}

func get(t *testing.T, h http.Handler, method, p string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, p, nil))
	return w
}

// Before setup is done every page path, the sign-in page at / included,
// goes to /setup; the stepper and the files the pages load are served.
func TestBeforeSetupEveryPageGoesToSetup(t *testing.T) {
	h := osadmin.PagesHandler(pageAssets, func(*http.Request) (string, error) { return osadmin.PhaseFirstBoot, nil }, nil)
	for _, p := range []string{"/", "/home", "/updates", "/access?x=1", "/index.html", "/assets", "/assets/", "/no-such-page", "/setupx"} {
		for _, m := range []string{http.MethodGet, http.MethodHead} {
			w := get(t, h, m, p)
			if w.Code != http.StatusFound || w.Header().Get("Location") != osadmin.SetupPath {
				t.Errorf("%s %s: %d %q", m, p, w.Code, w.Header().Get("Location"))
			}
		}
	}
	for _, p := range []string{"/setup", "/setup/", "/assets/app.js", "/assets/app.css", "/favicon.svg", "/assets/fonts/a.w"} {
		if w := get(t, h, http.MethodGet, p); w.Code != http.StatusOK {
			t.Errorf("GET %s: %d %q", p, w.Code, w.Header().Get("Location"))
		}
	}
	if w := get(t, h, http.MethodGet, "/setup"); w.Body.String() != "<html>admin</html>" {
		t.Errorf("/setup is the pages' index: %q", w.Body.String())
	}
}

func TestAfterSetupThePagesAreServed(t *testing.T) {
	h := osadmin.PagesHandler(pageAssets, func(*http.Request) (string, error) { return osadmin.PhaseNormal, nil }, nil)
	for _, p := range []string{"/", "/home", "/setup", "/assets/app.js"} {
		if w := get(t, h, http.MethodGet, p); w.Code != http.StatusOK {
			t.Errorf("GET %s: %d %q", p, w.Code, w.Header().Get("Location"))
		}
	}
}

// When the phase can't be read the pages are served as they are: the
// pages and the API still refuse what the phase doesn't allow.
func TestAnUnknownPhaseServesThePages(t *testing.T) {
	h := osadmin.PagesHandler(pageAssets, func(*http.Request) (string, error) { return "", errors.New("accessd is down") }, nil)
	if w := get(t, h, http.MethodGet, "/"); w.Code != http.StatusOK {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Location"))
	}
}

// The one-process handler gates its pages on the box's own phase.
func TestTheServerSendsPagesToSetupUntilItIsDone(t *testing.T) {
	b := newBox(t, false, func(_ *box, o *osadmin.Options) { o.Assets = pageAssets })
	hc := b.ts.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := hc.Get(b.ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != osadmin.SetupPath {
		t.Fatalf("before setup: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	b.finishSetup()
	res, err = hc.Get(b.ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("after setup: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func (b *box) phase() *osadminv1.GetPhaseResponse {
	b.t.Helper()
	st := osadminv1connect.NewStatusServiceClient(b.browser().hc, b.ts.URL)
	p, err := st.GetPhase(context.Background(), connect.NewRequest(&osadminv1.GetPhaseRequest{}))
	if err != nil {
		b.t.Fatal(err)
	}
	return p.Msg
}

// GetPhase says what the box is doing, for the product edge's box-state
// page: starting until setup is done and the product runs, running then,
// and init's announcement of a reboot or a shutdown over both.
func TestThePhaseSaysWhatTheBoxIsDoing(t *testing.T) {
	file := filepath.Join(t.TempDir(), "box-state")
	b := newBox(t, false, func(_ *box, o *osadmin.Options) { o.BoxStateFile = file })
	if p := b.phase(); p.GetState() != string(boxstate.Starting) || p.GetProductRunning() {
		t.Fatalf("before setup: %v", p)
	}
	b.finishSetup()
	if p := b.phase(); p.GetState() != string(boxstate.Starting) || p.GetProductRunning() || p.GetProductInstalled() {
		t.Fatalf("set up, no product running: %v", p)
	}
	b.installProduct("0.1.0")
	if p := b.phase(); !p.GetProductInstalled() {
		t.Fatalf("a product installed: %v", p)
	}
	b.services.mu.Lock()
	b.services.running = true
	b.services.mu.Unlock()
	if p := b.phase(); p.GetState() != string(boxstate.Running) || !p.GetProductRunning() {
		t.Fatalf("the product runs: %v", p)
	}
	for _, s := range []boxstate.State{boxstate.Rebooting, boxstate.ShuttingDown} {
		if err := boxstate.Announce(file, s); err != nil {
			t.Fatal(err)
		}
		if p := b.phase(); p.GetState() != string(s) || !p.GetProductRunning() || p.GetPhase() != osadmin.PhaseNormal {
			t.Fatalf("announced %s: %v", s, p)
		}
	}
}

// While an update applies the box is updating, and the reboot it ends in
// stays updating: the page says why the box went away.
func TestThePhaseSaysUpdatingWhileAnUpdateApplies(t *testing.T) {
	file := filepath.Join(t.TempDir(), "box-state")
	b := newBox(t, true, func(_ *box, o *osadmin.Options) { o.BoxStateFile = file })
	b.finishSetup()
	alice := b.browser()
	alice.signIn("alice")
	b.staged(alice)
	var during, rebooting string
	b.init.duringActivate = func() {
		during = b.phase().GetState()
		if err := boxstate.Announce(file, boxstate.Rebooting); err != nil {
			t.Error(err)
		}
		rebooting = b.phase().GetState()
	}
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	if during != string(boxstate.Updating) || rebooting != string(boxstate.Updating) {
		t.Fatalf("while the update applied: %q, then with the reboot announced: %q", during, rebooting)
	}
}

// installProduct makes version the installed product bundle.
func (b *box) installProduct(version string) {
	b.t.Helper()
	dir := filepath.Join(b.state, "product")
	if err := os.MkdirAll(filepath.Join(dir, "a"), 0o700); err != nil {
		b.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "bundle.json"), []byte(`{"version":"`+version+`"}`), 0o600); err != nil {
		b.t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(dir, "current")); err != nil {
		b.t.Fatal(err)
	}
}

// waitState asks the phase until it says want, or fails after a few
// seconds.
func (b *box) waitState(want boxstate.State) {
	b.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		p := b.phase()
		if p.GetState() == string(want) {
			return
		}
		if time.Now().After(deadline) {
			b.t.Fatalf("state %q, want %q", p.GetState(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (b *box) setRunning(on bool) {
	b.services.mu.Lock()
	b.services.running = on
	b.services.mu.Unlock()
}

// Once k0s runs the box still says starting until the product is ready
// (the same check a product apply waits on), so the edge keeps 443 on the
// box-state page and an open tab doesn't reload into a product whose
// services are still starting. Each k0s start waits again.
func TestThePhaseSaysStartingUntilTheProductIsReady(t *testing.T) {
	p := &fakeProbe{step: productup.StepPods, detail: "Rolling out (12 of 17 ready): waiting for sneakers/sneakers-audit"}
	b := newBox(t, false, withProbe(p))
	b.finishSetup()
	b.installProduct("0.1.0")
	b.setRunning(true)
	for range 20 {
		if got := b.phase(); got.GetState() != string(boxstate.Starting) || !got.GetProductRunning() {
			t.Fatalf("k0s runs, the product isn't ready: %v", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
	p.set("", "", nil)
	b.waitState(boxstate.Running)
	b.setRunning(false)
	if got := b.phase().GetState(); got != string(boxstate.Starting) {
		t.Fatalf("k0s stopped: %q", got)
	}
	p.set(productup.StepK0s, "The Kubernetes API doesn't answer yet.", nil)
	b.setRunning(true)
	for range 10 {
		if got := b.phase().GetState(); got != string(boxstate.Starting) {
			t.Fatalf("k0s started again, the product isn't ready: %q", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
	p.set("", "", nil)
	b.waitState(boxstate.Running)
}

// A product that isn't ready within its ready bound isn't served half
// started: the state goes to failed, and 443 stays on the box-state page,
// which says why.
func TestThePhaseSaysFailedAfterTheBound(t *testing.T) {
	p := &fakeProbe{step: productup.StepPods, detail: "4 of 5 pods ready"}
	b := newBox(t, false, withProbe(p))
	b.finishSetup()
	b.installProduct("0.1.0")
	b.setRunning(true)
	if got := b.phase().GetState(); got != string(boxstate.Starting) {
		t.Fatalf("not ready yet: %q", got)
	}
	b.clk.Advance(osadmin.ProductUpBound + time.Second)
	b.waitState(boxstate.Failed)
}

// From a product apply's restart until the product is ready the box says
// updating, so 443 shows "updating" and nobody signs in to a product that
// still rolls out; then it says running.
func TestThePhaseSaysUpdatingUntilAProductApplyIsReady(t *testing.T) {
	p := &fakeProbe{step: productup.StepPods, detail: "Rolling out (12 of 17 ready): waiting for sneakers/sneakers-audit"}
	b, alice := applyProductWith(t, p)
	b.finishSetup()
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE pods:ACTIVE product_health:PENDING edge:PENDING")
	if got := b.phase(); got.GetState() != string(boxstate.Updating) || !got.GetProductRunning() {
		t.Fatalf("rolling out: %v", got)
	}
	p.set("", "", nil)
	waitSteps(t, alice, "verify:DONE stage:DONE switch:DONE restart:DONE k0s:DONE images:DONE manifests:DONE pods:DONE product_health:DONE edge:DONE")
	b.waitState(boxstate.Running)
}
