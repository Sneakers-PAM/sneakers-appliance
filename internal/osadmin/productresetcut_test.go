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
		return string(raw)
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

// resume is a box's start: the part of settling a reset that holds it up,
// then what accessd leaves running beside it.
func resume(b *box) {
	if finish := b.srv.ResumeProductReset(context.Background()); finish != nil {
		finish()
	}
}

func resetEntry(t *testing.T, l *osaudit.Log, event string) osaudit.Entry {
	t.Helper()
	es, err := l.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		if e.Action == "product.reset" && e.Detail["event"] == event {
			return e
		}
	}
	t.Fatalf("no product.reset with event %q in %v", event, resetEntries(t, l))
	return osaudit.Entry{}
}

// Cut off once anything went, the product can't come back, so the box
// finishes the reset by itself at its next start, from the step it was cut
// off at. The audit log says the box did it, for the owner who asked.
func TestAResetCutOffPartWayFinishesAtTheNextStart(t *testing.T) {
	for _, c := range []struct {
		step string
		rest []string
	}{
		{"cluster", []string{"stop k0s", "start k0s", "cluster", "stop k0s", "data"}},
		{"data", []string{"stop k0s", "data"}},
		{"slot", []string{"stop k0s"}},
	} {
		t.Run(c.step, func(t *testing.T) {
			b, _, alice := resetBox(t)
			cutAt(t, b, c.step)
			resume(b)
			if got := b.services.log(); !slices.Equal(got, c.rest) {
				t.Fatalf("steps %v", got)
			}
			s := alice.productSlots(t)
			if recordStep(b) != "" || s.GetResetNote() != "" || s.GetResetFinishing() || s.GetInstalledVersion() != "" || s.GetStagedVersion() != "0.2.0" {
				t.Fatalf("record %q, slots %v", recordStep(b), s)
			}
			if got := resetEntries(t, b.log); !slices.Equal(got, []string{"started", "finished"}) {
				t.Fatalf("audit %v", got)
			}
			started, finished := resetEntry(t, b.log, "started"), resetEntry(t, b.log, "finished")
			if started.Actor != "system" || started.Detail["from"] != c.step || started.Detail["started_by"] != "alice" {
				t.Fatalf("started %+v", started)
			}
			if finished.Actor != "system" || finished.Outcome != "ok" || finished.Detail["started_by"] != "alice" || finished.Detail["version"] != "0.2.0" {
				t.Fatalf("finished %+v", finished)
			}
			if h := alice.upgrades(t).GetHistory()[0]; h.GetAction() != "reset" || h.GetOutcome() != "ok" || h.GetActor() != "system" || !strings.Contains(h.GetDetail(), "the box went on at its start") {
				t.Fatalf("history %v", h)
			}
		})
	}
}

// While the box finishes it, Status, Updates and the state say so, nothing
// is asked of an owner, and an owner's reset waits for it.
func TestTheBoxSaysItsFinishingACutOffReset(t *testing.T) {
	b, fake, alice := resetBox(t)
	cutAt(t, b, "data")
	finish := b.srv.ResumeProductReset(context.Background())
	if finish == nil {
		t.Fatal("nothing left to finish")
	}
	if _, err := resetAs(b, b.ssh("alice"), &osadminv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "sneakers"}); err == nil {
		t.Fatal("an owner's reset ran beside the box's")
	} else {
		symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_BUSY")
	}
	s := alice.productSlots(t)
	if !s.GetResetFinishing() || !strings.Contains(s.GetResetNote(), "the box is finishing it") {
		t.Fatalf("slots %v", s)
	}
	st := slotsStatus(t, alice)
	if !slices.ContainsFunc(st.GetWarnings(), func(w *osadminv1.Warning) bool {
		return w.GetKind() == osadminv1.WarningKind_WARNING_KIND_PRODUCT_RESET_CUT_OFF && w.GetDetail() == s.GetResetNote()
	}) {
		t.Fatalf("status warnings %v", st.GetWarnings())
	}
	if p := phaseOf(t, b, alice); p.GetState() == string(boxstate.Failed) {
		t.Fatalf("phase %v", p)
	}
	finish()
	if len(fake.removed) == 0 || recordStep(b) != "" {
		t.Fatalf("removed %v, record %q", fake.removed, recordStep(b))
	}
}

// A finish that fails leaves the record at its step. The product is held,
// and says so everywhere, until the next start tries again or an owner
// runs sneakers reset, which goes on from that step.
func TestACutOffResetTheBoxCantFinishIsHeld(t *testing.T) {
	b, fake, alice := resetBox(t)
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.3.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	cutAt(t, b, "data")
	fake.dataErr = errors.New("the disk said no")
	resume(b)
	if recordStep(b) != "data" {
		t.Fatalf("record %q", recordStep(b))
	}
	refused := resetEntries(t, b.log)
	if !slices.Equal(refused, []string{"started", ""}) {
		t.Fatalf("audit %v", refused)
	}
	if e := resetEntry(t, b.log, ""); e.Actor != "system" || e.Outcome != "refused" || e.Detail["step"] != "data" {
		t.Fatalf("the failed finish %+v", e)
	}
	s := alice.productSlots(t)
	note := s.GetResetNote()
	if s.GetResetFinishing() || !strings.Contains(note, "cut off") || !strings.Contains(note, "next start") || !strings.Contains(note, "sneakers reset") {
		t.Fatalf("slots %v", s)
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

	fake.dataErr = nil
	clearCalls(b)
	if _, err := resetAs(b, b.ssh("alice"), &osadminv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "sneakers"}); err != nil {
		t.Fatal(err)
	}
	if got := b.services.log(); !slices.Equal(got, []string{"stop k0s", "data"}) {
		t.Fatalf("steps %v", got)
	}
	s = alice.productSlots(t)
	if recordStep(b) != "" || s.GetResetNote() != "" || s.GetInstalledVersion() != "" || s.GetStagedVersion() != "0.2.0" {
		t.Fatalf("record %q, slots %v", recordStep(b), s)
	}
	e := resetEntry(t, b.log, "finished")
	if e.Actor != "alice" {
		t.Fatalf("finished %+v", e)
	}
}

// A record that can't be read doesn't say a reset ran, or how far: the box
// removes nothing on it and holds the product for an owner.
func TestAnUnreadableResetRecordIsHeldForAnOwner(t *testing.T) {
	for name, raw := range map[string]string{"garbled": "{", "unknown step": `{"step":"later"}`} {
		t.Run(name, func(t *testing.T) {
			b, fake, alice := resetBox(t)
			cutAt(t, b, "data")
			if err := os.WriteFile(recordPath(b), []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if finish := b.srv.ResumeProductReset(context.Background()); finish != nil {
				t.Fatal("the box went on from a record it can't read")
			}
			if got := b.services.log(); !slices.Equal(got, []string{"stop k0s"}) || len(fake.removed) != 0 {
				t.Fatalf("steps %v, removed %v", got, fake.removed)
			}
			if got := resetEntries(t, b.log); len(got) != 0 {
				t.Fatalf("audit %v", got)
			}
			s := alice.productSlots(t)
			if s.GetInstalledVersion() != "0.2.0" || !strings.Contains(s.GetResetNote(), "can't read") || !strings.Contains(s.GetResetNote(), "over SSH") {
				t.Fatalf("slots %v", s)
			}
			if _, err := resetAs(b, b.ssh("alice"), &osadminv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "sneakers"}); err != nil {
				t.Fatal(err)
			}
			if recordStep(b) != "" || alice.productSlots(t).GetInstalledVersion() != "" {
				t.Fatalf("record %q", recordStep(b))
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
