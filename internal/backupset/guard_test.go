// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package backupset

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

type guardBox struct {
	*fixture
	g      *Guard
	status string
	clock  time.Time
	seg    int
	audits []string
}

func newGuardBox(t *testing.T) *guardBox {
	t.Helper()
	f := newFixture(t)
	root := t.TempDir()
	d := filepath.Join(root, "db", "pgdata", "pg_wal", "archive_status")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	f.spec.Data = []productspec.DataPath{{Name: "database", Path: "db", WAL: "pgdata/pg_wal"}}
	f.spec.Backups.Data = "database"
	s := f.spec
	b := &guardBox{fixture: f, status: d, clock: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}
	b.g = &Guard{Spec: func() (productspec.Spec, error) { return s, nil }, Engine: f.e, DataRoot: root,
		StateFile: filepath.Join(root, "archive.json"), Now: func() time.Time { return b.clock },
		Audit: func(a string, _ map[string]string) { b.audits = append(b.audits, a) }}
	return b
}

func (b *guardBox) add(t *testing.T, n int) {
	t.Helper()
	for range n {
		b.seg++
		name := fmt.Sprintf("0000000100000000%08X.ready", b.seg)
		if err := os.WriteFile(filepath.Join(b.status, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func (b *guardBox) count(t *testing.T, suffix string) int {
	t.Helper()
	ents, err := os.ReadDir(b.status)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), suffix) {
			n++
		}
	}
	return n
}

func (b *guardBox) tick(d time.Duration) {
	b.clock = b.clock.Add(d)
	b.g.Tick(context.Background())
}

func TestAStuckArchiveLetsTheOldestGoAndKeepsTheLimit(t *testing.T) {
	b := newGuardBox(t)
	b.add(t, 80)
	b.tick(0)
	b.add(t, 1)
	b.tick(time.Minute)
	if got := b.count(t, doneSuffix); got != 0 {
		t.Fatalf("%d let go before the archive counted as stuck", got)
	}
	b.add(t, 1)
	b.tick(DefaultStuckAfter)
	if got, keep := b.count(t, readySuffix), DefaultHoldBytes/segmentBytes; got != keep {
		t.Fatalf("%d held, want %d", got, keep)
	}
	if got := b.count(t, doneSuffix); got != 82-DefaultHoldBytes/segmentBytes {
		t.Fatalf("%d let go", got)
	}
	if _, err := os.Stat(filepath.Join(b.status, "000000010000000000000001.done")); err != nil {
		t.Fatalf("the oldest wasn't the one let go: %v", err)
	}
	if len(b.audits) != 1 {
		t.Fatalf("audit = %v", b.audits)
	}
	w := b.g.Warnings()
	if len(w) == 0 || !strings.Contains(fmt.Sprint(w), "let 18 WAL files go") {
		t.Fatalf("warnings = %+v", w)
	}
}

func TestAMovingArchiveKeepsEverything(t *testing.T) {
	b := newGuardBox(t)
	b.add(t, 200)
	b.tick(0)
	// The archive takes the oldest between looks, however large the backlog.
	for i := range 30 {
		if err := os.Remove(filepath.Join(b.status, fmt.Sprintf("0000000100000000%08X.ready", i+1))); err != nil {
			t.Fatal(err)
		}
		b.add(t, 2)
		b.tick(time.Minute)
	}
	if got := b.count(t, doneSuffix); got != 0 {
		t.Fatalf("%d let go from an archive that's moving", got)
	}
}

func TestADatabaseThatIsntWritingIsLeftAlone(t *testing.T) {
	b := newGuardBox(t)
	b.add(t, 200)
	b.tick(0)
	b.tick(time.Hour)
	b.tick(time.Hour)
	if got := b.count(t, doneSuffix); got != 0 {
		t.Fatalf("%d let go with nothing growing", got)
	}
}

func TestACriticalVolumeDoesntWait(t *testing.T) {
	b := newGuardBox(t)
	b.g.Critical = func() bool { return true }
	b.add(t, 80)
	b.tick(0)
	if got := b.count(t, doneSuffix); got != 16 {
		t.Fatalf("%d let go", got)
	}
}

func TestTheNextBaseBackupClosesTheGap(t *testing.T) {
	b := newGuardBox(t)
	b.g.Critical = func() bool { return true }
	b.add(t, 80)
	b.tick(0)
	if !strings.Contains(fmt.Sprint(b.g.Warnings()), "WAL files go") {
		t.Fatalf("warnings = %+v", b.g.Warnings())
	}
	store := b.fixture.b.StoreHostDir()
	writeStore(t, store, "basebackups_005/base_000000010000000000000060/x")
	body := fmt.Sprintf(`{"LSN":1,"FinishTime":%q}`, b.clock.Add(time.Hour).Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(store, baseDir, "base_000000010000000000000060"+sentinelSuffix), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	b.tick(2 * time.Hour)
	if strings.Contains(fmt.Sprint(b.g.Warnings()), "WAL files go") {
		t.Fatalf("the gap outlived the base backup: %+v", b.g.Warnings())
	}
}

func TestStatusSaysWhatWentWrong(t *testing.T) {
	b := newGuardBox(t)
	b.tick(0)
	if !strings.Contains(fmt.Sprint(b.g.Warnings()), "no base backup yet") {
		t.Fatalf("warnings = %+v", b.g.Warnings())
	}
	b.add(t, 1)
	b.tick(0)
	b.tick(warnStuckAfter)
	if !strings.Contains(fmt.Sprint(b.g.Warnings()), "stood still") {
		t.Fatalf("warnings = %+v", b.g.Warnings())
	}
}

func TestUnfinishedFilesAreClearedOnceOld(t *testing.T) {
	b := newGuardBox(t)
	store := b.fixture.b.StoreHostDir()
	writeStore(t, store, "wal_005/000000010000000000000001.lz4", "wal_005/000000010000000000000002.lz4.tmp.20261101T194433Z-63f0")
	b.clock = time.Now()
	b.tick(0)
	if _, err := os.Stat(filepath.Join(store, walDir, "000000010000000000000002.lz4.tmp.20261101T194433Z-63f0")); err != nil {
		t.Fatal("a young file went")
	}
	b.tick(tmpAge + time.Minute)
	if _, err := os.Stat(filepath.Join(store, walDir, "000000010000000000000002.lz4.tmp.20261101T194433Z-63f0")); err == nil {
		t.Fatal("the old file stayed")
	}
	if _, err := os.Stat(filepath.Join(store, walDir, "000000010000000000000001.lz4")); err != nil {
		t.Fatal("a whole file went")
	}
}
