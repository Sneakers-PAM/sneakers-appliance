// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package datamove

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// The audit actions of a return (docs/os-audit.md).
const (
	ActionReverted = "upgrade.data-move-reverted"
	ActionReturn   = "upgrade.data-move-return"
	ActionKept     = "upgrade.data-move-kept"
)

// RevertNote is what a revert over a move means for the data. It goes
// everywhere the revert's outcome is reported.
const RevertNote = "The box is back on the old database as it stood at the move. What was written on the new database since stays there and isn't carried back. The next apply moves the old database again and first keeps the new database's data in a dump."

const (
	keptPrefix = "replaced-"
	keptStamp  = "20060102T150405Z"
	// roomHint ends a return's refusal: the box never makes room itself.
	roomHint = "; earlier kept dumps stay until an owner removes them with the dumps command"
)

var keptName = regexp.MustCompile(`^replaced-[0-9]{8}T[0-9]{6}Z$`)

// RecordRevert records a slot switch that left the target behind: holds says
// whether the slot now current has the named workload. It answers whether
// that was recorded just now. It asks the slot, not the caller's intent, so a
// switch cut off before this ran is recorded at the next start. A failed move
// isn't a revert: the services never settled on its target.
func (m *Move) RecordRevert(holds func(string) bool) (bool, error) {
	j, err := m.Read()
	if err != nil {
		return false, err
	}
	if j.State != StateDone && j.State != StateSwitched {
		return false, nil
	}
	if holds(j.Target) {
		m.logger().Debug("datamove: this slot is on the new database; nothing to record", log.F("state", string(j.State)))
		return false, nil
	}
	m.logger().Warn("datamove: the box went back over a move; the next apply moves the old database again", log.F("was", string(j.State)), log.F("target", j.Target))
	j.State, j.Returning, j.Reverted, j.Keeping, j.Kept, j.KeptNothing = StateReverted, true, m.now(), "", "", false
	if err := m.save(j); err != nil {
		return false, err
	}
	m.audit(ActionReverted, map[string]string{"target": j.Target, "note": RevertNote})
	return true, nil
}

// room refuses a move that won't fit. A return reads the target too, which
// has to answer here: nothing has stopped yet.
func (m *Move) room(ctx context.Context, j *Journal) error {
	src, tgt := m.Spec.Source, m.Spec.Target
	if !j.Returning {
		size, err := m.Engine.Size(ctx, src, m.Spec.Databases)
		if err != nil {
			return err
		}
		dump, volume := roomFor(size)
		return checkRoom(m.Disk, m.BackupDir, m.Volumes, dump, volume, "")
	}
	if err := m.Engine.WaitReady(ctx, tgt); err != nil {
		return fmt.Errorf("the new database: %w", err)
	}
	keep := false
	old, target := make([]int64, len(m.Spec.Databases)), make([]int64, len(m.Spec.Databases))
	for i, db := range m.Spec.Databases {
		n, err := m.Engine.Tables(ctx, tgt, db)
		if err != nil {
			return err
		}
		keep = keep || n > 0
		if old[i], err = m.Engine.Size(ctx, src, []string{db}); err != nil {
			return err
		}
		if target[i], err = m.Engine.Size(ctx, tgt, []string{db}); err != nil {
			return err
		}
	}
	keep = keep && j.Kept == "" && !j.KeptNothing
	dump, volume := returnRoom(old, target, keep)
	return checkRoom(m.Disk, m.BackupDir, m.Volumes, dump, volume, roomHint)
}

// keep dumps the target before a return clears it, and proves the dump. It
// runs once per return: after it, what's in the target may be a part of the
// old cluster's copy, which must never pass for the data it replaced.
func (m *Move) keep(ctx context.Context, j *Journal, full []string) error {
	if !j.Returning || j.Kept != "" || j.KeptNothing {
		return nil
	}
	if len(full) == 0 {
		m.logger().Info("datamove: the new database holds no tables; nothing to keep")
		j.KeptNothing = true
		if err := m.save(j); err != nil {
			return err
		}
		m.say("The new database holds nothing to keep")
		m.audit(ActionKept, map[string]string{"nothing": "true", "target": j.Target})
		return nil
	}
	name := keptPrefix + m.now().UTC().Format(keptStamp)
	j.Keeping = name
	if err := m.step(j, StepKeep); err != nil {
		return err
	}
	dir := filepath.Join(m.BackupDir, name)
	m.say("Keeping the new database's data in %s", dir)
	man, err := m.writeDump(ctx, m.Spec.Target, dir, full, "Keeping")
	if err != nil {
		return fmt.Errorf("keeping the new database's data: %w", err)
	}
	if err := m.verifyDump(dir, man); err != nil {
		return fmt.Errorf("keeping the new database's data: %w", err)
	}
	if err := syncDir(m.BackupDir); err != nil {
		return err
	}
	j.Keeping, j.Kept = "", name
	if err := m.step(j, StepKeep); err != nil {
		return err
	}
	bytes := man.Roles.Bytes
	for _, db := range man.Databases {
		bytes += db.Bytes
	}
	m.say("Kept the new database's data in %s", dir)
	m.audit(ActionKept, map[string]string{"dump": name, "path": dir, "databases": strings.Join(full, ","), "bytes": strconv.FormatInt(bytes, 10), "target": j.Target})
	return nil
}

// dropPartial removes a kept dump an attempt didn't finish. It holds what's
// still in the target, so nothing is lost with it.
func (m *Move) dropPartial(j *Journal) error {
	if j.Keeping == "" {
		return nil
	}
	m.logger().Info("datamove: removing a kept dump that wasn't finished", log.F("dump", j.Keeping))
	if err := m.remove(filepath.Join(m.BackupDir, j.Keeping)); err != nil {
		return fmt.Errorf("removing an unfinished dump: %w", err)
	}
	j.Keeping = ""
	return m.save(j)
}

func (m *Move) remove(p string) error {
	if m.Remove != nil {
		return m.Remove(p)
	}
	return os.RemoveAll(p)
}

// removeDump removes the working dump. It's worthless once the box has
// settled or is back on the old cluster, and holds password verifiers, but
// nothing fails over it: a failure is logged, kept in the journal and tried
// again at the next start.
func (m *Move) removeDump(j *Journal) {
	dir := m.dumpDir()
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) && j.DumpLeft == "" {
		return
	}
	left := ""
	if err := m.remove(dir); err != nil {
		m.logger().Warn("datamove: the dump can't be removed; the next start tries again", log.F("error", err.Error()))
		left = err.Error()
	} else {
		m.logger().Info("datamove: the dump is removed")
	}
	if left == j.DumpLeft {
		return
	}
	j.DumpLeft = left
	if err := m.save(j); err != nil {
		m.logger().Warn("datamove: the dump's state isn't recorded", log.F("error", err.Error()))
	}
}

// Tidy removes what nothing needs any more, for a box that's ready or just
// started: the working dump of a settled move, and what a failed attempt or
// a recorded revert left once the slot isn't the target's. A move in
// progress keeps everything. Kept dumps are never touched.
func (m *Move) Tidy(holds func(string) bool) {
	j, err := m.Read()
	if err != nil {
		m.logger().Warn("datamove: the journal can't be read, so nothing is tidied", log.F("error", err.Error()))
		return
	}
	switch j.State {
	case StateDone:
	case StateFailed, StateReverted:
		if holds(j.Target) {
			return
		}
	default:
		return
	}
	if err := m.dropPartial(j); err != nil {
		m.logger().Warn("datamove: an unfinished dump can't be removed; the next start tries again", log.F("error", err.Error()))
	}
	m.removeDump(j)
}

// KeptDump is one dump of the data a return replaced.
type KeptDump struct {
	Name string
	Path string
	At   time.Time
	// Bytes is what its files hold.
	Bytes int64
	// Whole: its manifest is there, so every file is.
	Whole bool
}

// KeptDumps lists the kept dumps, oldest first. One still being written isn't
// one yet.
func (m *Move) KeptDumps() ([]KeptDump, error) {
	j, err := m.Read()
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(m.BackupDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("datamove: list the kept dumps: %w", err)
	}
	out := []KeptDump{}
	for _, e := range ents {
		if !e.IsDir() || !keptName.MatchString(e.Name()) || e.Name() == j.Keeping {
			continue
		}
		k := KeptDump{Name: e.Name(), Path: filepath.Join(m.BackupDir, e.Name())}
		if k.At, err = time.Parse(keptStamp, strings.TrimPrefix(k.Name, keptPrefix)); err != nil {
			return nil, fmt.Errorf("datamove: list the kept dumps: %w", err)
		}
		files, err := os.ReadDir(k.Path)
		if err != nil {
			return nil, fmt.Errorf("datamove: list the kept dumps: %w", err)
		}
		for _, f := range files {
			fi, err := f.Info()
			if err != nil {
				return nil, fmt.Errorf("datamove: list the kept dumps: %w", err)
			}
			k.Bytes += fi.Size()
			k.Whole = k.Whole || f.Name() == manifestFile
		}
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b KeptDump) int { return a.At.Compare(b.At) })
	return out, nil
}

// RemoveKept removes one kept dump, for an owner who asked by name. A return
// that hasn't reached the box yet is refused: its target may be cleared on
// the strength of that dump.
func (m *Move) RemoveKept(name string) error {
	if !keptName.MatchString(name) {
		return codes.New(codes.DataMoveDump, "%q isn't a kept dump's name", name)
	}
	j, err := m.Read()
	if err != nil {
		return err
	}
	if j.Keeping == name || (j.Kept == name && j.State != StateDone) {
		return codes.New(codes.DataMoveDump, "%s is still needed: the box hasn't settled on the new database", name)
	}
	dir := filepath.Join(m.BackupDir, name)
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return codes.New(codes.DataMoveDump, "there's no kept dump %s", name)
	}
	if err := m.remove(dir); err != nil {
		return fmt.Errorf("datamove: remove %s: %w", name, err)
	}
	m.logger().Info("datamove: a kept dump is removed", log.F("dump", name))
	return nil
}
