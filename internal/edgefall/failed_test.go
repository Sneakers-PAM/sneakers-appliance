// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package edgefall_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/edgefall"
)

// A product that couldn't start keeps 443 on the box-state page, which
// says so with the phase and the reason accessd gives, never a
// half-started product.
func TestAFailedBoxSaysWhichPhaseAndWhy(t *testing.T) {
	w, src, _ := watcher(t)
	src.err = nil
	src.p = edgefall.Phase{ProductInstalled: true, ProductRunning: true, State: "failed", Step: "phase:identity",
		Detail: "Starting sign-in, identity and the vault: sneakers/sneakers-vault-7c9 CrashLoopBackOff"}
	w.Poll(context.Background())
	if w.State() != boxstate.Failed {
		t.Fatalf("state %q", w.State())
	}
	if got := w.Detail(); !strings.Contains(got, "sneakers-vault") {
		t.Fatalf("detail %q", got)
	}
	// A poll answers no detail; the pushed one holds while the box stays
	// failed.
	src.p.Detail, src.p.Step = "", ""
	w.Poll(context.Background())
	if got := w.Detail(); !strings.Contains(got, "sneakers-vault") {
		t.Fatalf("detail after a poll %q", got)
	}
	s := edgefall.NewServer(w.State)
	s.SetDetail(w.Detail)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get(edgefall.StateHeader) != "failed" {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get(edgefall.StateHeader))
	}
	if !strings.Contains(body, edgefall.WordsFor(boxstate.Failed).Title) || !strings.Contains(body, "Starting sign-in, identity and the vault: sneakers/sneakers-vault-7c9 CrashLoopBackOff") {
		t.Fatalf("the page: %s", body)
	}
	src.p = edgefall.Phase{ProductInstalled: true, ProductRunning: true, State: "starting"}
	w.Poll(context.Background())
	if w.Detail() != "" {
		t.Fatalf("a starting box keeps the failure's detail %q", w.Detail())
	}
}

// An edgefall that restarts while the box is failed has no push to go
// on: its first ask of GetPhase gives the phase and the reason, and it
// serves them on the page and the stream at once.
func TestARestartedEdgefallServesTheFailureFromItsFirstAsk(t *testing.T) {
	reason := "Starting sign-in, identity and the vault: sneakers/sneakers-vault-7c9 CrashLoopBackOff"
	res := &osadminv1.GetPhaseResponse{Phase: "normal", State: "failed", ProductRunning: true, ProductInstalled: true,
		FailedPhase: "phase:identity", FailedReason: reason}
	w := edgefall.NewWatcher(func(context.Context) (edgefall.Phase, error) { return edgefall.PhaseOf(res), nil }, t.TempDir()+"/box-state", nil)
	w.Poll(context.Background())
	if w.State() != boxstate.Failed || w.Detail() != reason {
		t.Fatalf("state %q detail %q", w.State(), w.Detail())
	}
	if ev := w.Events().Current(); ev.State != "failed" || ev.Step != "phase:identity" || ev.Detail != reason {
		t.Fatalf("the stream's event %+v", ev)
	}
	s := edgefall.NewServer(w.State)
	s.SetDetail(w.Detail)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(rec.Body.String(), reason) {
		t.Fatalf("the page: %s", rec.Body.String())
	}
	// A box that isn't failed carries no reason, even if one were sent.
	res = &osadminv1.GetPhaseResponse{Phase: "normal", State: "starting", ProductRunning: true, ProductInstalled: true, FailedReason: "stale"}
	if p := edgefall.PhaseOf(res); p.Step != "" || p.Detail != "" {
		t.Fatalf("a starting phase %+v", p)
	}
}
