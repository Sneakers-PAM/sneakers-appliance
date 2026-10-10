// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package edgefall_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
