// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/edgefall"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

// fakeEdge is edgefall's push socket: it records each pushed phase, in
// order, next to what init was told (the services' calls, the reboots).
type fakeEdge struct {
	mu     sync.Mutex
	b      *box
	pushed []edgefall.Phase
	// order is "push <state> <kind>" and init's calls, interleaved.
	order []string
	fail  error
}

func (f *fakeEdge) Notify(_ context.Context, p edgefall.Phase) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pushed = append(f.pushed, p)
	f.order = append(f.order, strings.TrimSpace("push "+p.State+" "+p.Kind))
	return f.fail
}

func (f *fakeEdge) phases() []edgefall.Phase {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.pushed)
}

func withEdge(e *fakeEdge) func(*box, *osadmin.Options) {
	return func(b *box, o *osadmin.Options) {
		e.b = b
		o.BoxEvents = e
	}
}

// firstIndex is the index of the first entry in s that starts with want.
func firstIndex(s []string, want string) int {
	for i, v := range s {
		if strings.HasPrefix(v, want) {
			return i
		}
	}
	return -1
}

// A product install tells edgefall it started, as updating with the kind
// product-apply, before the product's service is stopped; then each step.
func TestAProductApplyTellsTheEdgeBeforeTheProductStops(t *testing.T) {
	e := &fakeEdge{}
	p := &fakeProbe{step: productup.StepPods, detail: "Rolling out (3 of 5 ready)"}
	b := newBox(t, false, withProbe(p), withEdge(e))
	b.finishSetup()
	alice := b.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	stops := func() int { return slices.Index(b.services.log(), "stop "+osadmin.ProductService) }
	var atStop []edgefall.Phase
	b.services.onStop = func() { atStop = e.phases() }
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	if stops() < 0 {
		t.Fatal("the product wasn't stopped")
	}
	if !slices.ContainsFunc(atStop, func(p edgefall.Phase) bool { return p.State == "updating" && p.Kind == edgefall.KindProductApply }) {
		t.Fatalf("pushed before the stop: %+v", atStop)
	}
	waitPush(t, e, func(p edgefall.Phase) bool {
		return p.State == "updating" && p.Step == productup.StepPods && p.Detail != ""
	})
	p.set("", "", nil)
	waitPush(t, e, func(p edgefall.Phase) bool { return p.State == "running" })
}

// A base update tells edgefall before init activates the new release.
func TestABaseUpdateTellsTheEdgeBeforeItActivates(t *testing.T) {
	e := &fakeEdge{}
	b := newBox(t, true, withEdge(e))
	alice := b.browser()
	alice.signIn("alice")
	b.staged(alice)
	var atActivate []edgefall.Phase
	b.init.duringActivate = func() { atActivate = e.phases() }
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(atActivate, func(p edgefall.Phase) bool { return p.State == "updating" && p.Kind == edgefall.KindUpdate }) {
		t.Fatalf("pushed before the activation: %+v", atActivate)
	}
}

// A reboot or a shutdown from the Power page is pushed before init is
// asked; a reboot init refuses is taken back.
func TestAPowerRequestTellsTheEdgeFirst(t *testing.T) {
	e := &fakeEdge{}
	b := newBox(t, false, withEdge(e))
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	b.init.onReboot = func() { e.mu.Lock(); e.order = append(e.order, "init reboot"); e.mu.Unlock() }
	if _, err := alice.power().Reboot(ctx, connect.NewRequest(&osadminv1.RebootRequest{})); err != nil {
		t.Fatal(err)
	}
	if i, j := firstIndex(e.order, "push rebooting"), firstIndex(e.order, "init reboot"); i < 0 || j < 0 || i > j {
		t.Fatalf("order %v", e.order)
	}
	if _, err := alice.power().Shutdown(ctx, connect.NewRequest(&osadminv1.ShutdownRequest{})); err != nil {
		t.Fatal(err)
	}
	if got := e.phases(); got[len(got)-1].State != "shutting-down" {
		t.Fatalf("shutdown pushed %+v", got)
	}
	b.init.mu.Lock()
	b.init.rebootErr = errors.New("init refused")
	b.init.mu.Unlock()
	if _, err := alice.power().Reboot(ctx, connect.NewRequest(&osadminv1.RebootRequest{})); err == nil {
		t.Fatal("init's refusal came back as ok")
	}
	if got := e.phases(); !got[len(got)-1].Reset {
		t.Fatalf("a refused reboot isn't taken back: %+v", got[len(got)-1])
	}
}

// edgefall not answering never stops an update: the push is bounded and
// the update goes on.
func TestAnEdgeThatDoesntAnswerDoesntStopAnUpdate(t *testing.T) {
	e := &fakeEdge{fail: errors.New("connection refused")}
	b := newBox(t, true, withEdge(e))
	alice := b.browser()
	alice.signIn("alice")
	b.staged(alice)
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
}

func waitPush(t *testing.T, e *fakeEdge, ok func(edgefall.Phase) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, p := range e.phases() {
			if ok(p) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("not pushed; pushed %+v", e.phases())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// End to end on the box's own pieces: a product tab's stream (edgefall's
// /_box/events) already has the started apply when init is told to stop
// the product, through accessd's push to edgefall's push socket.
func TestAnOpenStreamHasTheStartedApplyBeforeTheProductStops(t *testing.T) {
	sock := filepath.Join(shortTemp(t), "push.sock")
	w := edgefall.NewWatcher(func(context.Context) (edgefall.Phase, error) {
		return edgefall.Phase{}, errors.New("no poll in this test")
	}, filepath.Join(t.TempDir(), "box-state"), nil)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ps := &http.Server{Handler: edgefall.PushHandler(w, nil), ReadHeaderTimeout: time.Second}
	go func() { _ = ps.Serve(ln) }()
	t.Cleanup(func() { _ = ps.Close() })
	h := edgefall.NewServer(w.State)
	h.SetEvents(w.Events())
	es := httptest.NewServer(h)
	t.Cleanup(es.Close)

	p := &fakeProbe{step: productup.StepPods}
	b := newBox(t, false, withProbe(p), func(_ *box, o *osadmin.Options) { o.BoxEvents = &edgefall.PushClient{Socket: sock} })
	b.finishSetup()
	alice := b.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, es.URL+edgefall.EventsPath, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	var mu sync.Mutex
	var got []string
	go func() {
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
			if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				var e struct {
					State string  `json:"state"`
					Kind  *string `json:"kind"`
				}
				_ = json.Unmarshal([]byte(data), &e)
				k := ""
				if e.Kind != nil {
					k = *e.Kind
				}
				mu.Lock()
				got = append(got, e.State+" "+k)
				mu.Unlock()
			}
		}
	}()
	seen := func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(got) }
	deadline := time.Now().Add(3 * time.Second)
	for len(seen()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no first event")
		}
		time.Sleep(5 * time.Millisecond)
	}
	var atStop []string
	b.services.onStop = func() { atStop = seen() }
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(atStop, "updating product-apply") {
		t.Fatalf("the stream had %v when the product was stopped", atStop)
	}
}

// shortTemp is a temp dir with a path short enough for a unix socket.
func shortTemp(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "ef")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}
