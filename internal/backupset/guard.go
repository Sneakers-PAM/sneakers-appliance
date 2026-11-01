// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package backupset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

const (
	// DefaultHoldBytes is the WAL a stuck archive may hold on the data
	// volume, past what PostgreSQL keeps for itself.
	DefaultHoldBytes = 1 << 30
	// DefaultStuckAfter is how long the archive must stand still before the
	// box stops holding WAL for it.
	DefaultStuckAfter = 5 * time.Minute
	// warnStuckAfter is how long the archive stands still before Status
	// says so.
	warnStuckAfter = 15 * time.Minute
	// tmpAge is the age of a file WAL-G left unfinished that the box clears.
	tmpAge = time.Hour
	// baseMaxAge is how old the newest base backup gets before Status says so.
	baseMaxAge  = 48 * time.Hour
	readySuffix = ".ready"
	doneSuffix  = ".done"
)

// Warning is one thing Status says about the backups. A backup problem is a
// warning and never a failure of the product: the database runs on.
type Warning struct {
	Detail   string
	Critical bool
}

// gap is the record of WAL the archive never got.
type gap struct {
	Files int       `json:"files"`
	First string    `json:"first"`
	Last  string    `json:"last"`
	At    time.Time `json:"at"`
}

// Guard keeps a stuck archive from filling the data volume. PostgreSQL keeps
// every WAL file until archive_command takes it, so a full backup partition
// would otherwise fill the volume the database runs on and stop it, and
// nothing in postgresql.conf bounds that: max_wal_size and
// max_slot_wal_keep_size don't apply to WAL waiting for the archive. Once the
// archive has stood still and the backlog is past the limit, the box marks
// the oldest waiting files as archived, which lets PostgreSQL recycle them.
// That costs the archive a gap, which the box records and reports, and which
// the next base backup closes; it never costs the database. No file is
// removed here: PostgreSQL does that.
type Guard struct {
	Spec    func() (productspec.Spec, error)
	Engine  Engine
	Restore *Restorer
	// StateFile keeps the gap across restarts.
	StateFile string
	// DataRoot is productspec.DataRoot unless a rehearsal says otherwise.
	DataRoot string
	// Critical is whether the data volume is at its critical level: the box
	// then doesn't wait for StuckAfter.
	Critical   func() bool
	HoldBytes  int64
	StuckAfter time.Duration
	Audit      func(action string, detail map[string]string)
	Logger     log.Logger
	Now        func() time.Time

	mu       sync.Mutex
	oldest   string
	since    time.Time
	lastN    int
	warnings []Warning
}

func (g *Guard) logger() log.Logger {
	if g.Logger == nil {
		return log.Nop()
	}
	return g.Logger
}

func (g *Guard) now() time.Time {
	if g.Now != nil {
		return g.Now().UTC()
	}
	return time.Now().UTC()
}

func (g *Guard) readGap() gap {
	var out gap
	b, err := os.ReadFile(g.StateFile)
	if err == nil {
		err = json.Unmarshal(b, &out)
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		g.logger().Warn("backupset: the archive's record doesn't read", log.F("error", err.Error()))
	}
	return out
}

func (g *Guard) writeGap(v gap) {
	b, err := json.Marshal(v)
	if err == nil {
		tmp := g.StateFile + ".tmp"
		if err = os.WriteFile(tmp, b, 0o600); err == nil {
			err = os.Rename(tmp, g.StateFile)
		}
	}
	if err != nil {
		g.logger().Warn("backupset: the archive's record wasn't written", log.F("error", err.Error()))
	}
}

// Tick is one look; accessd makes one a minute.
func (g *Guard) Tick(ctx context.Context) {
	s, err := g.Spec()
	if err != nil || s.Backups == nil {
		g.mu.Lock()
		g.warnings = nil
		g.mu.Unlock()
		return
	}
	if g.Restore != nil && g.Restore.Active() {
		return
	}
	stuckFor := g.hold(s)
	g.sweep(*s.Backups)
	w := g.report(ctx, *s.Backups, stuckFor)
	g.mu.Lock()
	g.warnings = w
	g.mu.Unlock()
}

// Warnings are what the last look found.
func (g *Guard) Warnings() []Warning {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.warnings)
}

func (g *Guard) statusDir(s productspec.Spec) string {
	d, ok := s.BackupData()
	if !ok || d.WAL == "" {
		return ""
	}
	root := g.DataRoot
	if root == "" {
		root = productspec.DataRoot
	}
	return filepath.Join(root, d.Path, d.WAL, "archive_status")
}

func readyFiles(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if bare, ok := strings.CutSuffix(e.Name(), readySuffix); ok && len(bare) == 24 {
			out = append(out, bare)
		}
	}
	slices.Sort(out)
	return out, nil
}

// hold applies the limit, and answers how long the archive has stood still.
func (g *Guard) hold(s productspec.Spec) time.Duration {
	dir := g.statusDir(s)
	if dir == "" {
		return 0
	}
	ready, err := readyFiles(dir)
	if err != nil {
		g.logger().Warn("backupset: the archive's backlog doesn't read", log.F("error", err.Error()))
		return 0
	}
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(ready) == 0 {
		g.oldest, g.lastN = "", 0
		return 0
	}
	if ready[0] != g.oldest {
		g.oldest, g.since = ready[0], now
	}
	stuckFor := now.Sub(g.since)
	limit := g.HoldBytes
	if limit <= 0 {
		limit = DefaultHoldBytes
	}
	after := g.StuckAfter
	if after <= 0 {
		after = DefaultStuckAfter
	}
	keep := int(limit / segmentBytes)
	// A database that isn't writing isn't filling anything, and the
	// archive may yet take what waits.
	growing := len(ready) > g.lastN
	g.lastN = len(ready)
	critical := g.Critical != nil && g.Critical()
	if len(ready) <= keep || !growing || (stuckFor < after && !critical) {
		return stuckFor
	}
	drop := ready[:len(ready)-keep]
	marked := 0
	for _, f := range drop {
		if err := os.Rename(filepath.Join(dir, f+readySuffix), filepath.Join(dir, f+doneSuffix)); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				g.logger().Error(err, "backupset: a stuck WAL file wasn't let go", log.F("file", f))
			}
			continue
		}
		marked++
	}
	if marked == 0 {
		return stuckFor
	}
	g.lastN -= marked
	g.oldest = ""
	rec := g.readGap()
	if rec.First == "" {
		rec.First, rec.At = drop[0], now
	}
	rec.Files += marked
	rec.Last = drop[len(drop)-1]
	g.writeGap(rec)
	g.logger().Warn("backupset: the archive is stuck, so WAL files were let go to keep the database running", log.F("files", marked), log.F("first", drop[0]), log.F("last", rec.Last), log.F("held", len(ready)-marked))
	if g.Audit != nil {
		g.Audit("product.backup.wal-dropped", map[string]string{"files": strconv.Itoa(marked), "first": drop[0], "last": rec.Last})
	}
	return stuckFor
}

// sweep clears what WAL-G left unfinished. On a full partition it leaves a
// file behind at every try, and those hold the room it needs.
func (g *Guard) sweep(b productspec.Backups) {
	dir := filepath.Join(b.StoreHostDir(), walDir)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !strings.Contains(e.Name(), tmpMark) {
			continue
		}
		info, err := e.Info()
		if err != nil || g.now().Sub(info.ModTime()) < tmpAge {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			g.logger().Warn("backupset: an unfinished file wasn't cleared", log.F("file", e.Name()), log.F("error", err.Error()))
		}
	}
}

func (g *Guard) report(ctx context.Context, b productspec.Backups, stuckFor time.Duration) []Warning {
	var out []Warning
	add := func(critical bool, format string, a ...any) {
		out = append(out, Warning{Detail: fmt.Sprintf(format, a...), Critical: critical})
	}
	if stuckFor >= warnStuckAfter {
		add(false, "WAL archiving has stood still for %d minutes, so the backups stop short of now. The usual cause is a full backup partition.", int(stuckFor.Minutes()))
	}
	all, err := bases(b.StoreHostDir())
	if err != nil {
		g.logger().Warn("backupset: the archive's base backups don't read", log.F("error", err.Error()))
	}
	var newest time.Time
	if len(all) > 0 {
		newest = all[len(all)-1].Finished
	}
	rec := g.readGap()
	if rec.First != "" {
		if newest.After(rec.At) {
			g.writeGap(gap{})
		} else {
			add(false, "The box let %d WAL files go without archiving them, from %s to %s, to keep the database running. Nothing can be restored past the gap from an earlier base backup; the next base backup closes it.", rec.Files, rec.First, rec.Last)
		}
	}
	switch {
	case len(all) == 0:
		add(false, "There's no base backup yet.")
	case g.now().Sub(newest) > baseMaxAge:
		add(false, "The newest base backup is from %s.", newest.Format(time.RFC3339))
	}
	if ann, err := g.Engine.Annotations(ctx, b); err == nil {
		failed, ok := parseTime(ann[b.Status.Failure]), parseTime(ann[b.Status.Success])
		if failed.After(ok) {
			add(false, "The last base backup failed at %s. The usual cause is a full backup partition.", failed.Format(time.RFC3339))
		}
		if at := parseTime(ann[b.Status.Verify]); !at.IsZero() && ann[b.Status.VerifyResult] != b.Status.VerifyOK {
			add(false, "The restore check at %s failed: the latest backup may not restore.", at.Format(time.RFC3339))
		}
	}
	if g.Restore != nil {
		if j, err := g.Restore.Read(); err == nil && j.State == StateFailed {
			add(false, "The restore of %s failed and the box went back to its data: %s.", j.Set, j.Why)
		}
	}
	return out
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}
