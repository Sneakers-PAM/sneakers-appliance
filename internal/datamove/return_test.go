// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package datamove

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// onTarget is a slot holding the new cluster, onOld one that doesn't.
func onTarget(string) bool { return true }
func onOld(string) bool    { return false }

type heard struct {
	action string
	detail map[string]string
}

// settled is a box healthy on the target, with its clock ticking and what it
// audits recorded.
func settled(t *testing.T) (*fixture, *[]heard) {
	t.Helper()
	f := newFixture(t)
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	f.m.Now = func() time.Time { now = now.Add(time.Minute); return now }
	log := &[]heard{}
	f.m.Audit = func(action string, detail map[string]string) { *log = append(*log, heard{action, detail}) }
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Settle(); err != nil {
		t.Fatal(err)
	}
	return f, log
}

func actions(log []heard) []string {
	out := []string{}
	for _, h := range log {
		out = append(out, h.action)
	}
	return out
}

func journal(t *testing.T, m *Move) *Journal {
	t.Helper()
	j, err := m.Read()
	if err != nil {
		t.Fatal(err)
	}
	return j
}

// reverted is a settled box an admin took back: the services wrote on the
// new cluster, then on the old one.
func reverted(t *testing.T) (*fixture, *[]heard) {
	t.Helper()
	f, log := settled(t)
	f.e.target[dbOne] = fakeDB{dump: "new side's one", counts: map[string]int64{"public.a": 9}}
	if ok, err := f.m.RecordRevert(onOld); err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	f.e.source[dbOne] = fakeDB{dump: "old side's one", counts: map[string]int64{"public.a": 4, "public.b": 0}}
	f.e.calls, f.svc.calls = nil, nil
	return f, log
}

func TestARevertOfASettledMoveIsRecorded(t *testing.T) {
	f, log := settled(t)
	ok, err := f.m.RecordRevert(onOld)
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	j := journal(t, f.m)
	if j.State != StateReverted || !j.Returning || j.Reverted.IsZero() {
		t.Fatalf("%+v", j)
	}
	if !slices.Contains(actions(*log), "upgrade.data-move-reverted") {
		t.Fatalf("%v", *log)
	}
	last := (*log)[len(*log)-1]
	if !strings.Contains(last.detail["note"], "stays there") || last.detail["note"] != RevertNote {
		t.Fatalf("%+v", last)
	}
	if ok, err := f.m.RecordRevert(onOld); ok || err != nil {
		t.Fatalf("recorded twice: %v %v", ok, err)
	}
}

func TestARevertThatStaysOnTheTargetRecordsNothing(t *testing.T) {
	f, log := settled(t)
	if ok, err := f.m.RecordRevert(onTarget); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if j := journal(t, f.m); j.State != StateDone || j.Returning {
		t.Fatalf("%+v", j)
	}
	if slices.Contains(actions(*log), "upgrade.data-move-reverted") {
		t.Fatalf("%v", *log)
	}
}

func TestARevertBeforeTheMoveSettledIsRecordedToo(t *testing.T) {
	f := newFixture(t)
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.m.RecordRevert(onOld); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if j := journal(t, f.m); j.State != StateReverted {
		t.Fatalf("%+v", j)
	}
}

func TestAFailedMoveIsNotARevert(t *testing.T) {
	f := newFixture(t)
	f.e.fail["restore:app_two new-db"] = errors.New("boom")
	if err := f.m.Run(context.Background()); err == nil {
		t.Fatal("no error")
	}
	if ok, err := f.m.RecordRevert(onOld); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if j := journal(t, f.m); j.State != StateFailed || j.Returning {
		t.Fatalf("%+v", j)
	}
}

func TestReturningKeepsTheTargetThenMovesFromTheOldCluster(t *testing.T) {
	f, log := reverted(t)
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	j := journal(t, f.m)
	if j.State != StateSwitched || j.Kept == "" || j.Keeping != "" {
		t.Fatalf("%+v", j)
	}
	if !strings.HasPrefix(j.Kept, "replaced-2026") {
		t.Fatalf("%q", j.Kept)
	}
	if f.e.target[dbOne].dump != "old side's one" {
		t.Fatalf("%+v", f.e.target[dbOne])
	}
	dir := filepath.Join(f.m.BackupDir, j.Kept)
	got, err := os.ReadFile(filepath.Join(dir, dbOne+".dump")) // #nosec G304 -- the test's own files
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new side's one" {
		t.Fatalf("kept %q", got)
	}
	man, err := readManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if man.Databases[0].Rows["public.a"] != 9 || man.Databases[0].SHA256 == "" || man.Roles.SHA256 == "" {
		t.Fatalf("%+v", man)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("%v %v", fi, err)
	}
	if i, k := slices.Index(f.e.calls, "dump:app_one new-db"), slices.Index(f.e.calls, "drop:app_one new-db"); i < 0 || k < i {
		t.Fatalf("the target was cleared before it was kept:\n%s", strings.Join(f.e.calls, "\n"))
	}
	if !slices.Contains(f.e.calls, "dump:app_one old-db") {
		t.Fatalf("it didn't dump the old cluster:\n%s", strings.Join(f.e.calls, "\n"))
	}
	for _, a := range []string{"upgrade.data-move-return", "upgrade.data-move-kept"} {
		if !slices.Contains(actions(*log), a) {
			t.Fatalf("no %s in %v", a, actions(*log))
		}
	}
	if err := f.m.Settle(); err != nil {
		t.Fatal(err)
	}
	if j := journal(t, f.m); j.State != StateDone || j.Returning {
		t.Fatalf("%+v", j)
	}
}

func TestKeptDumpsReadWhatTheStepSays(t *testing.T) {
	f, _ := reverted(t)
	var said []string
	f.m.Progress = func(s string) { said = append(said, s) }
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(said, "\n")
	for _, want := range []string{"Moving the old database again", "Keeping the new database's data", journal(t, f.m).Kept} {
		if !strings.Contains(all, want) {
			t.Fatalf("no %q in:\n%s", want, all)
		}
	}
}

func TestATargetWhoseVolumeIsGoneIsEmptyWithNothingToKeep(t *testing.T) {
	f, log := reverted(t)
	f.e.target = map[string]fakeDB{}
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	j := journal(t, f.m)
	if j.Kept != "" || !j.KeptNothing || j.State != StateSwitched {
		t.Fatalf("%+v", j)
	}
	ents, err := filepath.Glob(filepath.Join(f.m.BackupDir, "replaced-*"))
	if err != nil || len(ents) != 0 {
		t.Fatalf("%v %v", ents, err)
	}
	found := false
	for _, h := range *log {
		found = found || h.action == "upgrade.data-move-kept" && h.detail["nothing"] == "true"
	}
	if !found {
		t.Fatalf("%v", *log)
	}
}

func TestKeepingFailsBeforeTheTargetIsTouched(t *testing.T) {
	f, _ := reverted(t)
	f.e.fail["dump:app_two new-db"] = errors.New("cut off")
	err := f.m.Run(context.Background())
	if !codes.Is(err, codes.DataMove) {
		t.Fatalf("%v", err)
	}
	if f.e.target[dbOne].dump != "new side's one" {
		t.Fatalf("%+v", f.e.target)
	}
	for _, c := range f.e.calls {
		if strings.HasPrefix(c, "drop:") || strings.HasPrefix(c, "restore") {
			t.Fatalf("%s ran", c)
		}
	}
	j := journal(t, f.m)
	if j.State != StateFailed || j.Kept != "" || !j.Returning || j.Keeping == "" {
		t.Fatalf("%+v", j)
	}
	if slices.Contains(f.svc.calls, "start") {
		t.Fatal("the services started")
	}

	// The next apply starts over and finishes, with one kept dump.
	delete(f.e.fail, "dump:app_two new-db")
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	ents, err := filepath.Glob(filepath.Join(f.m.BackupDir, "replaced-*"))
	if err != nil || len(ents) != 1 || filepath.Base(ents[0]) != journal(t, f.m).Kept {
		t.Fatalf("%v %v", ents, err)
	}
}

func TestABadKeptDumpNeverClearsTheTarget(t *testing.T) {
	f, _ := reverted(t)
	f.e.before["counts:app_two new-db"] = func() {
		j := journal(t, f.m)
		p := filepath.Join(f.m.BackupDir, j.Keeping, dbOne+".dump")
		if err := os.WriteFile(p, []byte("changed"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := f.m.Run(context.Background())
	if !codes.Is(err, codes.DataMove) || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("%v", err)
	}
	if f.e.target[dbOne].dump != "new side's one" {
		t.Fatalf("%+v", f.e.target)
	}
}

func TestARetryAfterTheTargetWasClearedDoesNotKeepAPartialTarget(t *testing.T) {
	f, _ := reverted(t)
	f.e.fail["restore:app_two new-db"] = errors.New("boom")
	if err := f.m.Run(context.Background()); err == nil {
		t.Fatal("no error")
	}
	kept := journal(t, f.m).Kept
	if kept == "" {
		t.Fatal("nothing kept")
	}
	delete(f.e.fail, "restore:app_two new-db")
	f.e.calls = nil
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.e.calls, "dump:app_one new-db") {
		t.Fatal("the partly restored target was kept over the real one")
	}
	if journal(t, f.m).Kept != kept {
		t.Fatalf("%+v", journal(t, f.m))
	}
}

func TestACutOffReturnStartsOverOnTheNextApply(t *testing.T) {
	f, _ := reverted(t)
	j := journal(t, f.m)
	j.State, j.Step, j.Keeping = StateRunning, StepKeep, "replaced-20261101T120000Z"
	partial := filepath.Join(f.m.BackupDir, j.Keeping)
	if err := os.MkdirAll(partial, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := f.m.save(j); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Run(context.Background()); !errors.Is(err, ErrInterrupted) {
		t.Fatalf("%v", err)
	}
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(partial); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the partial dump stayed: %v", err)
	}
	if journal(t, f.m).Kept == "" {
		t.Fatalf("%+v", journal(t, f.m))
	}
}

func TestAReturnThatWontFitIsRefusedAndTouchesNothing(t *testing.T) {
	f, _ := reverted(t)
	f.e.size = 10 * int64(gib)
	f.m.Disk = func(string) (Usage, error) { return Usage{Avail: 8 * gib, Device: 1}, nil }
	f.e.sizes = map[string]int64{"old-db app_one": 2 * int64(gib), "old-db app_two": 2 * int64(gib), "new-db app_one": 10 * int64(gib), "new-db app_two": 10 * int64(gib)}
	f.e.size = 4 * int64(gib)
	err := f.m.Run(context.Background())
	if !codes.Is(err, codes.DataMoveRoom) {
		t.Fatalf("%v", err)
	}
	for _, c := range f.e.calls {
		if strings.HasPrefix(c, "dump") || strings.HasPrefix(c, "drop") {
			t.Fatalf("%s ran", c)
		}
	}
	if len(f.svc.calls) != 0 {
		t.Fatalf("%v", f.svc.calls)
	}
	if j := journal(t, f.m); j.State != StateFailed || !j.Returning {
		t.Fatalf("%+v", j)
	}
}

func TestReturnRoomCountsTheKeptDumpAndWhatClearingFrees(t *testing.T) {
	dump, volume := returnRoom(
		[]int64{10 * int64(gib), 4 * int64(gib)},
		[]int64{8 * int64(gib), 6 * int64(gib)},
		true)
	sourceDump, _ := roomFor(14 * int64(gib))
	keptDump, _ := roomFor(14 * int64(gib))
	if dump != sourceDump+keptDump {
		t.Fatalf("dump %s", gibs(dump))
	}
	if volume != 2*gib+uint64(walRoom) {
		t.Fatalf("volume %s", gibs(volume))
	}
	if dump, _ := returnRoom([]int64{int64(gib)}, []int64{int64(gib)}, false); dump != sourceDumpOf(int64(gib)) {
		t.Fatalf("dump %s with nothing to keep", gibs(dump))
	}
}

func sourceDumpOf(n int64) uint64 {
	d, _ := roomFor(n)
	return d
}

func TestAnEarlierKeptDumpIsNeverDroppedForRoom(t *testing.T) {
	f, _ := reverted(t)
	earlier := filepath.Join(f.m.BackupDir, "replaced-20260101T000000Z")
	if err := os.MkdirAll(earlier, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeSynced(filepath.Join(earlier, manifestFile), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	f.m.Disk = func(string) (Usage, error) { return Usage{Avail: 0, Device: 1}, nil }
	if err := f.m.Run(context.Background()); !codes.Is(err, codes.DataMoveRoom) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(earlier); err != nil {
		t.Fatal(err)
	}
}

func TestASecondRevertAndReturnRepeatsTheKeep(t *testing.T) {
	f, _ := reverted(t)
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Settle(); err != nil {
		t.Fatal(err)
	}
	first := journal(t, f.m).Kept
	if ok, err := f.m.RecordRevert(onOld); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if j := journal(t, f.m); j.Kept != "" || j.KeptNothing || !j.Returning {
		t.Fatalf("%+v", j)
	}
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := journal(t, f.m).Kept
	if second == "" || second == first {
		t.Fatalf("%q %q", first, second)
	}
	list, err := f.m.KeptDumps()
	if err != nil || len(list) != 2 {
		t.Fatalf("%+v %v", list, err)
	}
}

func TestAForeignTargetIsStillRefusedOnAReturn(t *testing.T) {
	f, _ := reverted(t)
	j := journal(t, f.m)
	j.TargetTouched = false
	if err := f.m.save(j); err != nil {
		t.Fatal(err)
	}
	err := f.m.Run(context.Background())
	if !codes.Is(err, codes.DataMove) || !strings.Contains(err.Error(), "didn't put it there") {
		t.Fatalf("%v", err)
	}
	if f.e.target[dbOne].dump != "new side's one" {
		t.Fatalf("%+v", f.e.target)
	}
	if slices.Contains(f.e.calls, "dump:app_one new-db") {
		t.Fatal("it kept a target it was going to refuse")
	}
}

func TestTheWorkingDumpGoesAtSettle(t *testing.T) {
	f, _ := settled(t)
	if _, err := os.Stat(f.m.dumpDir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the dump stayed: %v", err)
	}
	if j := journal(t, f.m); j.State != StateDone || j.DumpLeft != "" {
		t.Fatalf("%+v", j)
	}
}

func TestARemovalThatFailsNeverFailsTheBoxAndIsRetried(t *testing.T) {
	f := newFixture(t)
	f.m.Remove = func(string) error { return errors.New("the disk said no") }
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Settle(); err != nil {
		t.Fatalf("a failed removal failed the settle: %v", err)
	}
	j := journal(t, f.m)
	if j.State != StateDone || !strings.Contains(j.DumpLeft, "the disk said no") {
		t.Fatalf("%+v", j)
	}
	if _, err := os.Stat(f.m.dumpDir()); err != nil {
		t.Fatal(err)
	}
	f.m.Remove = nil
	f.m.Tidy(onTarget)
	if j := journal(t, f.m); j.DumpLeft != "" {
		t.Fatalf("%+v", j)
	}
	if _, err := os.Stat(f.m.dumpDir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the dump stayed: %v", err)
	}
}

func TestAFailedAttemptsDumpGoesOnceTheBoxIsBackOnTheOldCluster(t *testing.T) {
	f := newFixture(t)
	f.e.fail["restore:app_two new-db"] = errors.New("boom")
	if err := f.m.Run(context.Background()); err == nil {
		t.Fatal("no error")
	}
	f.m.Tidy(onTarget)
	if _, err := os.Stat(f.m.dumpDir()); err != nil {
		t.Fatalf("it went while the box was still on the move's slot: %v", err)
	}
	f.m.Tidy(onOld)
	if _, err := os.Stat(f.m.dumpDir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the dump stayed: %v", err)
	}
}

func TestTidyLeavesARunningOrSwitchedMoveAlone(t *testing.T) {
	f := newFixture(t)
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.m.Tidy(onOld)
	if _, err := os.Stat(f.m.dumpDir()); err != nil {
		t.Fatalf("switched: %v", err)
	}
	j := journal(t, f.m)
	j.State = StateRunning
	if err := f.m.save(j); err != nil {
		t.Fatal(err)
	}
	f.m.Tidy(onOld)
	if _, err := os.Stat(f.m.dumpDir()); err != nil {
		t.Fatalf("running: %v", err)
	}
}

func TestKeptDumpsAreNeverRemovedByTheBox(t *testing.T) {
	f, _ := reverted(t)
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Settle(); err != nil {
		t.Fatal(err)
	}
	f.m.Tidy(onTarget)
	f.m.Tidy(onOld)
	list, err := f.m.KeptDumps()
	if err != nil || len(list) != 1 || list[0].Name != journal(t, f.m).Kept || list[0].Bytes == 0 {
		t.Fatalf("%+v %v", list, err)
	}
	if list[0].Path != filepath.Join(f.m.BackupDir, list[0].Name) {
		t.Fatalf("%+v", list[0])
	}
}

func TestRemovingAKeptDump(t *testing.T) {
	f, log := reverted(t)
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	name := journal(t, f.m).Kept

	// Until the box settles, it's the only copy that return depends on.
	if err := f.m.RemoveKept(name); !codes.Is(err, codes.DataMoveDump) {
		t.Fatalf("%v", err)
	}
	if err := f.m.Settle(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"../platform", "dump", "replaced-20261101T120000Z/../..", "replaced-20200101T000000Z"} {
		if err := f.m.RemoveKept(bad); !codes.Is(err, codes.DataMoveDump) {
			t.Fatalf("%s: %v", bad, err)
		}
	}
	if err := f.m.RemoveKept(name); err != nil {
		t.Fatal(err)
	}
	if list, err := f.m.KeptDumps(); err != nil || len(list) != 0 {
		t.Fatalf("%+v %v", list, err)
	}
	_ = log
}

func TestTheRunnerAnswersWithoutASlotThatDeclaresAMove(t *testing.T) {
	f, _ := settled(t)
	r := runner(f)
	if ok, err := r.RecordRevert(onOld); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	r.Tidy(onOld)
	if list, err := r.KeptDumps(); err != nil || len(list) != 0 {
		t.Fatalf("%+v %v", list, err)
	}
	st := until(t, r, f.svc)
	if !st.Done {
		t.Fatalf("%+v", st)
	}
	if !slices.Contains(f.e.calls, "dump:app_one old-db") {
		t.Fatal("the return didn't run")
	}
}
