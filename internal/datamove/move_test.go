// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package datamove

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

const (
	gib     = uint64(1) << 30
	dbOne   = "app_one"
	dbTwo   = "app_two"
	srcName = "old-db"
	tgtName = "new-db"
)

// fakeDB stands in for one database of a cluster.
type fakeDB struct {
	dump   string
	counts map[string]int64
}

// fakeEngine is two clusters in memory. Every call is recorded; fail makes
// the named call fail, and before runs ahead of the named call.
type fakeEngine struct {
	t       *testing.T
	calls   []string
	source  map[string]fakeDB
	target  map[string]fakeDB
	roles   string
	tgtRole string
	size    int64
	fail    map[string]error
	before  map[string]func()
	check   string
}

func newEngine(t *testing.T) *fakeEngine {
	return &fakeEngine{
		t: t,
		source: map[string]fakeDB{
			dbOne: {dump: "dump of one", counts: map[string]int64{"public.a": 3, "public.b": 0}},
			dbTwo: {dump: "dump of two", counts: map[string]int64{"public.c": 7}},
		},
		target: map[string]fakeDB{},
		roles:  "CREATE ROLE app;\n",
		size:   int64(gib),
		fail:   map[string]error{},
		before: map[string]func(){},
		check:  "ok\n",
	}
}

func (f *fakeEngine) step(name string, c productspec.DataCluster, writes bool) error {
	f.t.Helper()
	call := name + " " + c.Name
	f.calls = append(f.calls, call)
	if writes && c.Name == srcName {
		f.t.Fatalf("%s writes to the source cluster", name)
	}
	if h := f.before[call]; h != nil {
		h()
	}
	return f.fail[call]
}

func (f *fakeEngine) WaitReady(_ context.Context, c productspec.DataCluster) error {
	return f.step("ready", c, false)
}

func (f *fakeEngine) Size(_ context.Context, c productspec.DataCluster, _ []string) (int64, error) {
	return f.size, f.step("size", c, false)
}

func (f *fakeEngine) of(c productspec.DataCluster) map[string]fakeDB {
	if c.Name == srcName {
		return f.source
	}
	return f.target
}

func (f *fakeEngine) Tables(_ context.Context, c productspec.DataCluster, db string) (int, error) {
	return len(f.of(c)[db].counts), f.step("tables", c, false)
}

func (f *fakeEngine) DumpRoles(_ context.Context, c productspec.DataCluster, w io.Writer) error {
	if err := f.step("dumproles", c, false); err != nil {
		return err
	}
	_, err := io.WriteString(w, f.roles)
	return err
}

func (f *fakeEngine) DumpDatabase(_ context.Context, c productspec.DataCluster, db string, w io.Writer) error {
	if err := f.step("dump:"+db, c, false); err != nil {
		return err
	}
	_, err := io.WriteString(w, f.source[db].dump)
	return err
}

func (f *fakeEngine) RestoreRoles(_ context.Context, c productspec.DataCluster, r io.Reader) error {
	if err := f.step("restoreroles", c, true); err != nil {
		return err
	}
	b, err := io.ReadAll(r)
	f.tgtRole = string(b)
	return err
}

func (f *fakeEngine) DropDatabase(_ context.Context, c productspec.DataCluster, db string) error {
	if err := f.step("drop:"+db, c, true); err != nil {
		return err
	}
	delete(f.target, db)
	return nil
}

func (f *fakeEngine) RestoreDatabase(_ context.Context, c productspec.DataCluster, db string, r io.Reader) error {
	if err := f.step("restore:"+db, c, true); err != nil {
		return err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	f.target[db] = fakeDB{dump: string(b), counts: maps.Clone(f.source[db].counts)}
	return nil
}

func (f *fakeEngine) Counts(_ context.Context, c productspec.DataCluster, db string) (map[string]int64, error) {
	err := f.step("counts:"+db, c, false)
	return maps.Clone(f.of(c)[db].counts), err
}

func (f *fakeEngine) Check(_ context.Context, c productspec.DataCluster, db string, _ []byte) (string, error) {
	return f.check, f.step("check:"+db, c, false)
}

type fakeServices struct {
	calls []string
	stop  error
	start error
}

func (s *fakeServices) Stop(context.Context) error {
	s.calls = append(s.calls, "stop")
	return s.stop
}

func (s *fakeServices) Start(context.Context) error {
	s.calls = append(s.calls, "start")
	return s.start
}

func moveSpec() productspec.DataMove {
	return productspec.DataMove{
		Label: "Moving", After: "data", Databases: []string{dbOne, dbTwo},
		Source: productspec.DataCluster{Namespace: "app", Name: srcName, Host: "127.0.0.1", User: "postgres"},
		Target: productspec.DataCluster{Namespace: "app", Name: tgtName, Host: "new.app.svc", SSLMode: "require", User: "postgres"},
		Checks: []productspec.DataCheck{{Name: "chain", Database: dbOne, File: "datamove/chain.sql"}},
	}
}

type fixture struct {
	m   *Move
	e   *fakeEngine
	svc *fakeServices
	dir string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	slot := filepath.Join(dir, "slot")
	if err := os.MkdirAll(filepath.Join(slot, "datamove"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slot, "datamove", "chain.sql"), []byte("SELECT 'ok';"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, svc := newEngine(t), &fakeServices{}
	m := &Move{
		Spec: moveSpec(), Slot: slot,
		BackupDir: filepath.Join(dir, "backup"), Journal: filepath.Join(dir, "state", "data-move.json"), Volumes: filepath.Join(dir, "volumes"),
		Engine: e, Services: svc,
		Disk: func(p string) (Usage, error) {
			if strings.HasSuffix(p, "volumes") {
				return Usage{Avail: 100 * gib, Device: 2}, nil
			}
			return Usage{Avail: 100 * gib, Device: 1}, nil
		},
	}
	return &fixture{m: m, e: e, svc: svc, dir: dir}
}

func TestAMoveRunsItsStepsInOrder(t *testing.T) {
	f := newFixture(t)
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ready old-db", "size old-db", "tables old-db",
		"dumproles old-db",
		"dump:app_one old-db", "counts:app_one old-db",
		"dump:app_two old-db", "counts:app_two old-db",
		"ready new-db", "tables new-db", "tables new-db",
		"restoreroles new-db",
		"drop:app_one new-db", "restore:app_one new-db", "counts:app_one new-db",
		"drop:app_two new-db", "restore:app_two new-db", "counts:app_two new-db",
		"check:app_one new-db",
	}
	if !slices.Equal(f.e.calls, want) {
		t.Fatalf("calls:\n%s", strings.Join(f.e.calls, "\n"))
	}
	if !slices.Equal(f.svc.calls, []string{"stop", "start"}) {
		t.Fatalf("services: %v", f.svc.calls)
	}
	j, err := f.m.Read()
	if err != nil {
		t.Fatal(err)
	}
	if j.State != StateSwitched || !j.TargetTouched {
		t.Fatalf("%+v", j)
	}
	if f.e.target[dbOne].dump != "dump of one" || f.e.tgtRole != f.e.roles {
		t.Fatalf("restored %+v", f.e.target)
	}
}

func TestTheDumpIsPrivateAndCarriesItsChecksums(t *testing.T) {
	f := newFixture(t)
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(f.m.dumpDir()))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("dump directory %v", fi.Mode().Perm())
	}
	man, err := readManifest(f.m.dumpDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(man.Databases) != 2 || man.Roles.SHA256 == "" || man.Databases[0].Rows["public.a"] != 3 {
		t.Fatalf("%+v", man)
	}
	for _, name := range []string{manifestFile, man.Roles.File, man.Databases[0].File, f.m.Journal} {
		p := name
		if !filepath.IsAbs(p) {
			p = filepath.Join(f.m.dumpDir(), name)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s is %v", name, fi.Mode().Perm())
		}
	}
}

func TestAMoveThatFailsLeavesTheOldClusterAlone(t *testing.T) {
	steps := []string{
		"ready old-db", "size old-db", "dumproles old-db", "dump:app_two old-db", "counts:app_one old-db",
		"ready new-db", "restoreroles new-db", "restore:app_one new-db", "restore:app_two new-db",
		"counts:app_two new-db", "check:app_one new-db",
	}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			f := newFixture(t)
			f.e.fail[step] = errors.New("boom")
			err := f.m.Run(context.Background())
			if !codes.Is(err, codes.DataMove) {
				t.Fatalf("%v", err)
			}
			if slices.Contains(f.svc.calls, "start") {
				t.Fatal("the services started on a failed move")
			}
			j, rerr := f.m.Read()
			if rerr != nil {
				t.Fatal(rerr)
			}
			if j.State != StateFailed || j.Reason == "" {
				t.Fatalf("%+v", j)
			}
		})
	}
}

func TestARowCountThatDiffersFailsTheMove(t *testing.T) {
	cases := map[string]func(map[string]int64) map[string]int64{
		"a row short":   func(m map[string]int64) map[string]int64 { m["public.a"] = 2; return m },
		"a table gone":  func(m map[string]int64) map[string]int64 { delete(m, "public.b"); return m },
		"a table extra": func(m map[string]int64) map[string]int64 { m["public.z"] = 1; return m },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.e.before["counts:app_one new-db"] = func() {
				db := f.e.target[dbOne]
				db.counts = change(db.counts)
				f.e.target[dbOne] = db
			}
			err := f.m.Run(context.Background())
			if !codes.Is(err, codes.DataMove) || !strings.Contains(err.Error(), "public.") {
				t.Fatalf("%v", err)
			}
		})
	}
}

func TestACheckThatDoesNotSayOKFailsTheMove(t *testing.T) {
	f := newFixture(t)
	f.e.check = "broken at 17\n"
	err := f.m.Run(context.Background())
	if !codes.Is(err, codes.DataMove) || !strings.Contains(err.Error(), "broken at 17") {
		t.Fatalf("%v", err)
	}
}

func TestACheckMissingFromTheSlotFailsBeforeTheServicesStop(t *testing.T) {
	f := newFixture(t)
	if err := os.Remove(filepath.Join(f.m.Slot, "datamove", "chain.sql")); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Run(context.Background()); !codes.Is(err, codes.DataMove) {
		t.Fatalf("%v", err)
	}
	if len(f.svc.calls) != 0 {
		t.Fatalf("services: %v", f.svc.calls)
	}
}

func TestADumpChangedOnDiskIsNeverRestored(t *testing.T) {
	f := newFixture(t)
	f.e.before["ready new-db"] = func() {
		man, err := readManifest(f.m.dumpDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.m.dumpDir(), man.Databases[1].File), []byte("changed"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := f.m.Run(context.Background())
	if !codes.Is(err, codes.DataMove) || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("%v", err)
	}
	if slices.Contains(f.e.calls, "restore:app_two new-db") {
		t.Fatal("restored a changed dump")
	}
}

func TestATargetWithDataTheMoveDidNotPutThereIsRefused(t *testing.T) {
	f := newFixture(t)
	f.e.target[dbTwo] = fakeDB{counts: map[string]int64{"public.keep": 1}}
	err := f.m.Run(context.Background())
	if !codes.Is(err, codes.DataMove) || !strings.Contains(err.Error(), dbTwo) {
		t.Fatalf("%v", err)
	}
	if _, ok := f.e.target[dbTwo]; !ok || slices.Contains(f.e.calls, "drop:app_two new-db") {
		t.Fatal("the move dropped data it didn't write")
	}
}

func TestAnAttemptAfterAFailureStartsFromAnEmptyTarget(t *testing.T) {
	f := newFixture(t)
	f.e.fail["restore:app_two new-db"] = errors.New("boom")
	if err := f.m.Run(context.Background()); err == nil {
		t.Fatal("no failure")
	}
	f.e.fail = map[string]error{}
	f.e.calls = nil
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.e.calls, "drop:app_one new-db") {
		t.Fatalf("the partial restore stayed: %v", f.e.calls)
	}
	if j, _ := f.m.Read(); j.State != StateSwitched || j.Attempt != 2 {
		t.Fatalf("%+v", j)
	}
}

func TestTheJournalSaysTheTargetIsTouchedBeforeTheFirstWrite(t *testing.T) {
	f := newFixture(t)
	f.e.before["restoreroles new-db"] = func() {
		if j, err := f.m.Read(); err != nil || !j.TargetTouched {
			t.Fatalf("on disk: %+v %v", j, err)
		}
	}
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAMoveCutOffOnAnEarlierRunFails(t *testing.T) {
	f := newFixture(t)
	if err := f.m.save(&Journal{State: StateRunning, Step: StepRestore, TargetTouched: true}); err != nil {
		t.Fatal(err)
	}
	err := f.m.Run(context.Background())
	if !codes.Is(err, codes.DataMove) || !errors.Is(err, ErrInterrupted) {
		t.Fatalf("%v", err)
	}
	if len(f.e.calls) != 0 || len(f.svc.calls) != 0 {
		t.Fatal("a cut-off move ran on")
	}
	j, _ := f.m.Read()
	if j.State != StateFailed || !j.TargetTouched {
		t.Fatalf("%+v", j)
	}
}

func TestAFinishedMoveDoesNothing(t *testing.T) {
	for _, st := range []State{StateSwitched, StateDone} {
		f := newFixture(t)
		if err := f.m.save(&Journal{State: st}); err != nil {
			t.Fatal(err)
		}
		if err := f.m.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(f.e.calls) != 0 || len(f.svc.calls) != 0 {
			t.Fatal("ran again")
		}
	}
}

func TestANewBoxHasNothingToMove(t *testing.T) {
	f := newFixture(t)
	f.e.source = map[string]fakeDB{}
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	j, _ := f.m.Read()
	if j.State != StateDone || !j.Nothing {
		t.Fatalf("%+v", j)
	}
	if len(f.svc.calls) != 0 {
		t.Fatalf("services: %v", f.svc.calls)
	}
}

func TestAMoveThatWillNotFitIsRefusedAndSaysWhatItNeeds(t *testing.T) {
	f := newFixture(t)
	f.e.size = int64(5 * gib)
	f.m.Disk = func(string) (Usage, error) {
		return Usage{Avail: 4 * gib, Device: 1}, nil
	}
	err := f.m.Run(context.Background())
	if !codes.Is(err, codes.DataMoveRoom) || !strings.Contains(err.Error(), "GiB") {
		t.Fatalf("%v", err)
	}
	if len(f.svc.calls) != 0 {
		t.Fatal("the services stopped for a move that can't fit")
	}
}

func TestRoomCountsOneVolumeOnce(t *testing.T) {
	data := int64(5 * gib)
	dump, volume := roomFor(data)
	if dump < uint64(data)*30/100 || volume < uint64(data) {
		t.Fatalf("dump %d volume %d", dump, volume)
	}
	apart := func(p string) (Usage, error) {
		if p == "/backup" {
			return Usage{Avail: dump, Device: 1}, nil
		}
		return Usage{Avail: volume, Device: 2}, nil
	}
	if err := checkRoom(apart, "/backup", "/volumes", data); err != nil {
		t.Fatal(err)
	}
	shared := func(string) (Usage, error) {
		return Usage{Avail: dump + volume - 1, Device: 1}, nil
	}
	if err := checkRoom(shared, "/backup", "/volumes", data); !codes.Is(err, codes.DataMoveRoom) {
		t.Fatalf("%v", err)
	}
}

func TestServicesThatWillNotStopFailTheMove(t *testing.T) {
	f := newFixture(t)
	f.svc.stop = errors.New("still running")
	if err := f.m.Run(context.Background()); !codes.Is(err, codes.DataMove) {
		t.Fatalf("%v", err)
	}
	if slices.Contains(f.e.calls, "dumproles old-db") {
		t.Fatal("dumped with the services running")
	}
}

func TestServicesThatWillNotStartFailTheMove(t *testing.T) {
	f := newFixture(t)
	f.svc.start = errors.New("no")
	if err := f.m.Run(context.Background()); !codes.Is(err, codes.DataMove) {
		t.Fatalf("%v", err)
	}
	if j, _ := f.m.Read(); j.State != StateFailed {
		t.Fatalf("%+v", j)
	}
}

func TestSettleAndFailMoveTheJournalOn(t *testing.T) {
	f := newFixture(t)
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Fail("the gateway never came up"); err != nil {
		t.Fatal(err)
	}
	if j, _ := f.m.Read(); j.State != StateFailed || j.Reason != "the gateway never came up" {
		t.Fatalf("%+v", j)
	}
	if err := f.m.Settle(); err == nil {
		t.Fatal("settled a failed move")
	}

	g := newFixture(t)
	if err := g.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := g.m.Settle(); err != nil {
		t.Fatal(err)
	}
	if j, _ := g.m.Read(); j.State != StateDone {
		t.Fatalf("%+v", j)
	}
	if err := g.m.Fail("too late"); err != nil {
		t.Fatal(err)
	}
	if j, _ := g.m.Read(); j.State != StateDone {
		t.Fatalf("a settled move failed: %+v", j)
	}
}

func TestProgressNamesEachDatabaseAndNoValue(t *testing.T) {
	f := newFixture(t)
	var said bytes.Buffer
	f.m.Progress = func(s string) { fmt.Fprintln(&said, s) }
	if err := f.m.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Saving " + dbOne + " (1 of 2)", "Restoring " + dbTwo + " (2 of 2)", "Checking chain"} {
		if !strings.Contains(said.String(), want) {
			t.Errorf("no %q in\n%s", want, said.String())
		}
	}
}
