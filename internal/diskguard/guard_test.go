// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package diskguard_test

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/diskguard"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

type entries struct {
	mu sync.Mutex
	es []osaudit.Entry
}

func (e *entries) Append(x osaudit.Entry) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.es = append(e.es, x)
	return nil
}

func (e *entries) actions(prefix string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, x := range e.es {
		if strings.HasPrefix(x.Action, prefix) {
			out = append(out, x.Action+":"+x.Detail["level"])
		}
	}
	return out
}

func (e *entries) last(action string) (osaudit.Entry, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := len(e.es) - 1; i >= 0; i-- {
		if e.es[i].Action == action {
			return e.es[i], true
		}
	}
	return osaudit.Entry{}, false
}

// disks is a fake statfs: each path's use in percent of 100 GiB, with a
// device per path unless set.
type disks struct {
	mu  sync.Mutex
	pct map[string]float64
	dev map[string]uint64
}

func (d *disks) set(p string, pct float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pct[p] = pct
}

func (d *disks) statfs(p string) (diskguard.Usage, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	total := uint64(100 << 30)
	used := uint64(d.pct[p] * float64(total) / 100)
	dev := d.dev[p]
	if dev == 0 {
		dev = uint64(len(p))
	}
	return diskguard.Usage{Total: total, Used: used, Avail: total - used, Device: dev}, nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type countStep struct{ n int }

func (s *countStep) Category() string { return "count" }
func (s *countStep) Clean(context.Context, diskguard.Env) (diskguard.Result, error) {
	s.n++
	return diskguard.Result{Freed: 10}, nil
}

func newGuard(t *testing.T, d *disks, clk *clock, a *entries, steps ...diskguard.Step) *diskguard.Guard {
	t.Helper()
	return &diskguard.Guard{
		Volumes:   []diskguard.Volume{{Name: "state", Label: "State", Path: "/state"}, {Name: "backup", Label: "Backup", Path: "/backup"}},
		Cleaner:   &diskguard.Cleaner{Steps: steps, Audit: a, Now: clk.now, Statfs: d.statfs, StatePath: "/state"},
		Audit:     a,
		StateFile: filepath.Join(t.TempDir(), "guard.json"),
		Statfs:    d.statfs,
		DirSize:   func(string) (int64, error) { return 0, nil },
		Now:       clk.now,
	}
}

func TestNextLevelHysteresis(t *testing.T) {
	for _, c := range []struct {
		cur  diskguard.Level
		pct  float64
		want diskguard.Level
	}{
		{diskguard.LevelOK, 79.9, diskguard.LevelOK},
		{diskguard.LevelOK, 80, diskguard.LevelWarning},
		{diskguard.LevelOK, 90, diskguard.LevelCritical},
		{diskguard.LevelWarning, 75, diskguard.LevelWarning},
		{diskguard.LevelWarning, 74.9, diskguard.LevelOK},
		{diskguard.LevelCritical, 85, diskguard.LevelCritical},
		{diskguard.LevelCritical, 84.9, diskguard.LevelWarning},
		{diskguard.LevelCritical, 70, diskguard.LevelOK},
	} {
		if got := diskguard.NextLevel(c.cur, c.pct); got != c.want {
			t.Errorf("%v at %.1f%%: %v, want %v", c.cur, c.pct, got, c.want)
		}
	}
}

// Each alert is audited once as it starts and once as it clears, and a
// use that wobbles around a threshold doesn't flap.
func TestAlertsStartAndClearWithHysteresis(t *testing.T) {
	d := &disks{pct: map[string]float64{}, dev: map[string]uint64{}}
	clk := &clock{t: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	a := &entries{}
	g := newGuard(t, d, clk, a)
	g.Cleaner = nil
	for _, pct := range []float64{50, 82, 79, 83, 76, 74, 91, 88, 86, 84, 80, 70} {
		d.set("/state", pct)
		g.Tick(context.Background())
		clk.t = clk.t.Add(time.Minute)
	}
	got := strings.Join(a.actions("disk.alert."), " ")
	want := "disk.alert.start:warning disk.alert.clear:warning disk.alert.start:critical disk.alert.clear:critical disk.alert.clear:warning"
	if got != want {
		t.Fatalf("audit\n got %s\nwant %s", got, want)
	}
	e, _ := a.last(diskguard.ActionAlertClear)
	if e.Detail["volume"] != "state" || e.Detail["now"] != "ok" || e.Target != "State volume" || e.Actor != "disk-guard" {
		t.Fatalf("%+v", e)
	}
}

// A volume that passes its warning level is cleaned up at once; the next
// minute isn't, and the hour's timer runs again.
func TestCleanupOnAlertAndEveryHour(t *testing.T) {
	d := &disks{pct: map[string]float64{"/state": 40}, dev: map[string]uint64{}}
	clk := &clock{t: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	a := &entries{}
	st := &countStep{}
	g := newGuard(t, d, clk, a, st)
	g.Tick(context.Background())
	if st.n != 1 {
		t.Fatalf("first tick: %d runs, want the timer's first", st.n)
	}
	clk.t = clk.t.Add(time.Minute)
	g.Tick(context.Background())
	if st.n != 1 {
		t.Fatalf("a minute on: %d runs", st.n)
	}
	d.set("/state", 85)
	clk.t = clk.t.Add(time.Minute)
	g.Tick(context.Background())
	if st.n != 2 {
		t.Fatalf("passing 80%%: %d runs", st.n)
	}
	e, ok := a.last(diskguard.ActionCleanup)
	if !ok || e.Detail["trigger"] != "alert" || e.Detail["freed.count"] != "10" || e.Detail["freed"] != "10" || e.Target != "disk" {
		t.Fatalf("%+v", e)
	}
	clk.t = clk.t.Add(time.Minute)
	g.Tick(context.Background())
	if st.n != 2 {
		t.Fatalf("still over 80%%: %d runs; only a rise runs one at once", st.n)
	}
	clk.t = clk.t.Add(time.Hour)
	g.Tick(context.Background())
	if e, _ := a.last(diskguard.ActionCleanup); st.n != 3 || e.Detail["trigger"] != "timer" {
		t.Fatalf("an hour on: %d runs, %+v", st.n, e)
	}
	run := g.CleanUp(context.Background(), "alice")
	if e, _ := a.last(diskguard.ActionCleanup); run.Freed != 10 || e.Actor != "alice" || e.Detail["trigger"] != "admin" {
		t.Fatalf("an admin's run: %+v %+v", run, e)
	}
	if r := g.Report(); r.Cleanup == nil || r.Cleanup.Actor != "alice" {
		t.Fatalf("the report's last cleanup: %+v", r.Cleanup)
	}
}

// A volume on the same filesystem as an earlier one has no alert of its
// own.
func TestSharedVolumeAlertsOnce(t *testing.T) {
	d := &disks{pct: map[string]float64{"/state": 95, "/data": 95}, dev: map[string]uint64{"/state": 7, "/data": 7}}
	clk := &clock{t: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	a := &entries{}
	g := newGuard(t, d, clk, a)
	g.Cleaner = nil
	g.Volumes = append(g.Volumes, diskguard.Volume{Name: "data", Label: "Product data", Path: "/data"})
	r := g.Tick(context.Background())
	if got := a.actions("disk.alert."); len(got) != 1 {
		t.Fatalf("alerts %v", got)
	}
	if r.Volumes[2].SharedWith != "state" {
		t.Fatalf("%+v", r.Volumes[2])
	}
	var space []diskguard.Warning
	for _, w := range r.Warnings {
		if w.Kind == diskguard.WarnSpace {
			space = append(space, w)
		}
	}
	if len(space) != 1 || !space[0].Critical || !strings.Contains(space[0].Detail, "state volume is 95% full") {
		t.Fatalf("%+v", space)
	}
}

// The levels are kept across a restart: a box that comes back still full
// doesn't audit the alert again.
func TestLevelsSurviveRestart(t *testing.T) {
	d := &disks{pct: map[string]float64{"/state": 85}, dev: map[string]uint64{}}
	clk := &clock{t: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	a := &entries{}
	g := newGuard(t, d, clk, a)
	g.Cleaner = nil
	g.Tick(context.Background())
	g2 := newGuard(t, d, clk, a)
	g2.Cleaner, g2.StateFile = nil, g.StateFile
	clk.t = clk.t.Add(time.Minute)
	g2.Tick(context.Background())
	if got := a.actions("disk.alert."); len(got) != 1 {
		t.Fatalf("alerts %v", got)
	}
}

// A volume that would fill within a week at the last day's rate warns,
// and a data path's write-ahead log over its limit does too.
func TestGrowthAndWALWarnings(t *testing.T) {
	d := &disks{pct: map[string]float64{"/state": 40}, dev: map[string]uint64{}}
	clk := &clock{t: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)}
	a := &entries{}
	g := newGuard(t, d, clk, a)
	g.Cleaner = nil
	size := int64(1 << 30)
	g.Watches = func() []diskguard.Watch {
		return []diskguard.Watch{{Name: "database", Label: "The database", Path: "/data/db", WAL: "pg_wal", WALWarn: 1 << 30}}
	}
	g.DirSize = func(p string) (int64, error) {
		if strings.HasSuffix(p, "pg_wal") {
			return 3 << 30, nil
		}
		return size, nil
	}
	var r diskguard.Report
	for h := range 7 {
		d.set("/state", 40+float64(h)*2)
		size += 1 << 30
		r = g.Tick(context.Background())
		clk.t = clk.t.Add(time.Hour)
	}
	var kinds []string
	for _, w := range r.Warnings {
		kinds = append(kinds, w.Kind)
	}
	if !strings.Contains(strings.Join(kinds, " "), diskguard.WarnGrowth) || !strings.Contains(strings.Join(kinds, " "), diskguard.WarnWAL) {
		t.Fatalf("warnings %v", r.Warnings)
	}
	if len(r.Watches) != 1 || r.Watches[0].GrowthPerDay <= 0 || r.Watches[0].WALSize != 3<<30 {
		t.Fatalf("%+v", r.Watches)
	}
}

// A one-off fill isn't a day's growth: two samples an hour apart don't
// warn that the volume "grew" 24 times the jump in the last day. Steady
// growth over hours warns with what it really grew, over that span.
func TestGrowthWarningSaysWhatReallyGrew(t *testing.T) {
	d := &disks{pct: map[string]float64{"/state": 40}, dev: map[string]uint64{}}
	clk := &clock{t: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)}
	g := newGuard(t, d, clk, &entries{})
	g.Cleaner = nil
	growth := func(r diskguard.Report) string {
		for _, w := range r.Warnings {
			if w.Kind == diskguard.WarnGrowth {
				return w.Detail
			}
		}
		return ""
	}
	g.Tick(context.Background())
	clk.t = clk.t.Add(time.Hour)
	d.set("/state", 77)
	if w := growth(g.Tick(context.Background())); w != "" {
		t.Fatalf("a one-hour fill warns as a day's growth: %q", w)
	}
	for range 6 {
		clk.t = clk.t.Add(time.Hour)
		d.set("/state", d.pct["/state"]+1)
		g.Tick(context.Background())
	}
	w := growth(g.Tick(context.Background()))
	if !strings.Contains(w, "in the last 7 hours") || strings.Contains(w, "in the last day") || strings.Contains(w, "about less") {
		t.Fatalf("growth warning %q", w)
	}
}

// A data path the last sample doesn't have yet (the product's paths came
// after it) is measured for the report, not shown as 0 B until the next
// hourly sample.
func TestADataPathNewerThanTheLastSampleIsMeasured(t *testing.T) {
	d := &disks{pct: map[string]float64{"/state": 40}, dev: map[string]uint64{}}
	clk := &clock{t: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)}
	g := newGuard(t, d, clk, &entries{})
	g.Cleaner = nil
	g.DirSize = func(string) (int64, error) { return 5 << 30, nil }
	g.Tick(context.Background())
	g.Watches = func() []diskguard.Watch {
		return []diskguard.Watch{{Name: "database", Label: "The database", Path: "/data/db"}}
	}
	clk.t = clk.t.Add(time.Minute)
	r := g.Tick(context.Background())
	if len(r.Watches) != 1 || r.Watches[0].Size != 5<<30 {
		t.Fatalf("%+v", r.Watches)
	}
}

// The OS audit archive's flagged files show as a warning before they move.
func TestAuditArchiveWarning(t *testing.T) {
	d := &disks{pct: map[string]float64{"/state": 40}, dev: map[string]uint64{}}
	clk := &clock{t: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)}
	g := newGuard(t, d, clk, &entries{})
	g.Cleaner = nil
	g.Archive = func() *osaudit.ArchiveReport {
		return &osaudit.ArchiveReport{Flagged: []string{"log-2025-01-02.jsonl.gz"}, FlaggedBytes: 2048, ExportAfter: clk.t.Add(24 * time.Hour)}
	}
	r := g.Tick(context.Background())
	if len(r.Warnings) != 1 || r.Warnings[0].Kind != diskguard.WarnAuditArchive || !strings.Contains(r.Warnings[0].Detail, "from 2025-01-02") {
		t.Fatalf("%+v", r.Warnings)
	}
}

// Files past retention that the archive can't take stay, with a warning.
func TestPruneBlockedWarning(t *testing.T) {
	d := &disks{pct: map[string]float64{"/state": 40}, dev: map[string]uint64{}}
	clk := &clock{t: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)}
	g := newGuard(t, d, clk, &entries{})
	g.Cleaner = nil
	g.PruneBlocked = func() []osaudit.PruneBlock {
		return []osaudit.PruneBlock{{File: "log-2025-01-02.jsonl.gz", Reason: "os audit: no space left on device"}}
	}
	r := g.Tick(context.Background())
	if len(r.Warnings) != 1 || r.Warnings[0].Kind != diskguard.WarnAuditArchive || !strings.Contains(r.Warnings[0].Detail, "past their retention stay") || !strings.Contains(r.Warnings[0].Detail, "no space left") {
		t.Fatalf("%+v", r.Warnings)
	}
}
