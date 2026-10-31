// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect" // scrub:allow=fqdn

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxstate"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productreset"
)

func recordPath(b *box) string {
	return filepath.Join(b.state, "platform", productreset.RecordFile)
}

// recordStep is the step the reset's record on the state volume names, or
// "" with none.
func recordStep(b *box) string {
	raw, err := os.ReadFile(recordPath(b))
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	if err != nil {
		panic(err)
	}
	var r struct {
		Step string `json:"step"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		panic(err)
	}
	return r.Step
}

// cutAt leaves the box as a reset cut off at step does: the record names
// the step, and nothing of the run that wrote it is left.
func cutAt(t *testing.T, b *box, step string) {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"product": "sneakers", "title": "Sneakers", "version": "0.2.0", "actor": "alice", "step": step})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(recordPath(b)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath(b), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func resetEntries(t *testing.T, l *osaudit.Log) []string {
	t.Helper()
	es, err := l.Entries()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		if e.Action == "product.reset" {
			out = append(out, e.Detail["event"])
		}
	}
	return out
}

func clearCalls(b *box) {
	b.services.mu.Lock()
	defer b.services.mu.Unlock()
	b.services.calls = nil
}

func slotsStatus(t *testing.T, br *browser) *osadminv1.GetStatusResponse {
	t.Helper()
	st, err := osadminv1connect.NewStatusServiceClient(br.hc, br.b.ts.URL).GetStatus(context.Background(), connect.NewRequest(&osadminv1.GetStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return st.Msg
}

func phaseOf(t *testing.T, b *box, br *browser) *osadminv1.GetPhaseResponse {
	t.Helper()
	p, err := osadminv1connect.NewStatusServiceClient(br.hc, b.ts.URL).GetPhase(context.Background(), connect.NewRequest(&osadminv1.GetPhaseRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return p.Msg
}

// The reset says what it's about on the disk before it removes anything,
// keeps it to the step it's on, and drops it once it's done; the audit log
// has it as started and as finished.
func TestTheResetRecordsItsIntentFirst(t *testing.T) {
	b, fake, _ := resetBox(t)
	b.services.running = true
	if _, err := resetAs(b, b.ssh("alice"), &osadminv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "sneakers"}); err != nil {
		t.Fatal(err)
	}
	for what, want := range map[string]string{"quiesce": "quiesce", "cluster": "cluster", "data": "data"} {
		if fake.seen[what] != want {
			t.Fatalf("at %s the record said %q", what, fake.seen[what])
		}
	}
	if recordStep(b) != "" {
		t.Fatalf("the record stayed at %s", recordStep(b))
	}
	if got := resetEntries(t, b.log); !slices.Equal(got, []string{"started", "finished"}) {
		t.Fatalf("audit %v", got)
	}
}

// A reset that fails before anything was removed took nothing: the
// product stays, with no record holding it.
func TestAResetThatFailsBeforeRemovingLeavesNoRecord(t *testing.T) {
	b, fake, alice := resetBox(t)
	b.services.running = true
	fake.clusterErr = errors.New("k0s's API didn't answer")
	if _, err := resetAs(b, b.ssh("alice"), &osadminv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "sneakers"}); err == nil {
		t.Fatal("reset")
	}
	if recordStep(b) != "" || alice.productSlots(t).GetResetNote() != "" {
		t.Fatalf("record %q, note %q", recordStep(b), alice.productSlots(t).GetResetNote())
	}
}

// Cut off while the product was only stopping, nothing was lost: at its
// next start the box drops the reset, says so, and the product comes back.
func TestAResetCutOffBeforeRemovingIsAbandoned(t *testing.T) {
	b, _, alice := resetBox(t)
	cutAt(t, b, "quiesce")
	b.srv.ResumeProductReset(context.Background())
	if got := b.services.log(); !slices.Equal(got, []string{"stop k0s", "start k0s"}) {
		t.Fatalf("steps %v", got)
	}
	if recordStep(b) != "" || alice.productSlots(t).GetResetNote() != "" {
		t.Fatalf("record %q, note %q", recordStep(b), alice.productSlots(t).GetResetNote())
	}
	if got := resetEntries(t, b.log); !slices.Equal(got, []string{"abandoned"}) {
		t.Fatalf("audit %v", got)
	}
	if h := alice.upgrades(t).GetHistory()[0]; h.GetAction() != "reset" || h.GetOutcome() != "failed" || !strings.Contains(h.GetDetail(), "before anything was removed") {
		t.Fatalf("history %v", h)
	}
	if s := alice.productSlots(t); s.GetInstalledVersion() != "0.2.0" {
		t.Fatalf("slots %v", s)
	}
}

// Cut off once anything went, the product can't come back: k0s stays
// stopped, Status, Updates and the box state say why, a product update is
// refused, and sneakers reset goes on from the step it was cut off at.
func TestAResetCutOffPartWayHoldsTheProductUntilItsFinished(t *testing.T) {
	for _, c := range []struct {
		step string
		rest []string
	}{
		{"cluster", []string{"start k0s", "cluster", "stop k0s", "data"}},
		{"data", []string{"stop k0s", "data"}},
		{"slot", []string{"stop k0s"}},
	} {
		t.Run(c.step, func(t *testing.T) {
			b, _, alice := resetBox(t)
			id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.3.0", "0.1.0"))
			if err := stage(alice, id); err != nil {
				t.Fatal(err)
			}
			cutAt(t, b, c.step)
			b.srv.ResumeProductReset(context.Background())
			if got := b.services.log(); !slices.Equal(got, []string{"stop k0s"}) {
				t.Fatalf("steps at the start %v", got)
			}
			if recordStep(b) != c.step {
				t.Fatalf("record %q", recordStep(b))
			}
			note := alice.productSlots(t).GetResetNote()
			if !strings.Contains(note, "cut off") || !strings.Contains(note, "sneakers reset") {
				t.Fatalf("note %q", note)
			}
			st := slotsStatus(t, alice)
			if !slices.ContainsFunc(st.GetWarnings(), func(w *osadminv1.Warning) bool {
				return w.GetKind() == osadminv1.WarningKind_WARNING_KIND_PRODUCT_RESET_CUT_OFF && w.GetDetail() == note && w.GetCritical()
			}) {
				t.Fatalf("status warnings %v", st.GetWarnings())
			}
			p := phaseOf(t, b, alice)
			if p.GetState() != string(boxstate.Failed) || p.GetFailedReason() != note {
				t.Fatalf("phase %v", p)
			}
			_, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")}))
			symbolIn(t, err, connect.CodeFailedPrecondition, "PRODUCT_RESET")

			clearCalls(b)
			if _, err := resetAs(b, b.ssh("alice"), &osadminv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "sneakers"}); err != nil {
				t.Fatal(err)
			}
			if got := b.services.log(); !slices.Equal(got, c.rest) {
				t.Fatalf("steps %v", got)
			}
			s := alice.productSlots(t)
			if recordStep(b) != "" || s.GetResetNote() != "" || s.GetInstalledVersion() != "" || s.GetStagedVersion() != "0.2.0" {
				t.Fatalf("record %q, slots %v", recordStep(b), s)
			}
			if got := resetEntries(t, b.log); !slices.Equal(got[len(got)-2:], []string{"started", "finished"}) {
				t.Fatalf("audit %v", got)
			}
		})
	}
}

// Cut off with the slot already taken away, everything went: the box
// finishes the reset itself at its next start.
func TestAResetCutOffAfterTheSlotWentFinishesAtTheNextStart(t *testing.T) {
	b, _, alice := resetBox(t)
	product := filepath.Join(b.state, "product")
	if err := os.Remove(filepath.Join(product, "staged")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(product, "current"), filepath.Join(product, "staged")); err != nil {
		t.Fatal(err)
	}
	cutAt(t, b, "slot")
	b.srv.ResumeProductReset(context.Background())
	if recordStep(b) != "" || alice.productSlots(t).GetResetNote() != "" {
		t.Fatalf("record %q, note %q", recordStep(b), alice.productSlots(t).GetResetNote())
	}
	if got := resetEntries(t, b.log); !slices.Equal(got, []string{"finished"}) {
		t.Fatalf("audit %v", got)
	}
	if got := b.services.log(); len(got) != 0 {
		t.Fatalf("steps %v", got)
	}
	// What's staged waits for an owner, as the bundle a finished reset kept.
	if b := alice.productSlots(t); b.GetStagedVersion() != "0.2.0" {
		t.Fatalf("slots %v", b)
	}
}
