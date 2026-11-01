// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package datamove moves a product's databases to a new PostgreSQL cluster
// as one step of an upgrade (docs/data-move.md), once unless a revert goes
// back over it (return.go). It dumps the
// databases and roles to the backup partition with a checksum each,
// restores them into the target product.yaml names, compares every table's
// row count, runs the product's checks and only then lets the services
// start. It never writes to the source: the old cluster and its volume are
// the way back, and any failure leaves them as they were for the box to go
// back to. The package names no chart and no product.
package datamove

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// Engine is what a move needs of a PostgreSQL cluster. PG is the box's;
// nothing a move does to a source goes beyond reading.
type Engine interface {
	// WaitReady waits until the cluster takes a connection as declared.
	WaitReady(ctx context.Context, c productspec.DataCluster) error
	// Size is the databases' size on disk, in bytes.
	Size(ctx context.Context, c productspec.DataCluster, dbs []string) (int64, error)
	// Tables is how many user tables db has; 0 when it doesn't exist.
	Tables(ctx context.Context, c productspec.DataCluster, db string) (int, error)
	DumpRoles(ctx context.Context, c productspec.DataCluster, w io.Writer) error
	DumpDatabase(ctx context.Context, c productspec.DataCluster, db string, w io.Writer) error
	RestoreRoles(ctx context.Context, c productspec.DataCluster, r io.Reader) error
	DropDatabase(ctx context.Context, c productspec.DataCluster, db string) error
	RestoreDatabase(ctx context.Context, c productspec.DataCluster, db string, r io.Reader) error
	// Counts is every user table's row count, by schema.table.
	Counts(ctx context.Context, c productspec.DataCluster, db string) (map[string]int64, error)
	// Check runs a product's check query and returns what it printed.
	Check(ctx context.Context, c productspec.DataCluster, db string, query []byte) (string, error)
}

// Services stops and starts everything that connects to the database.
type Services interface {
	Stop(ctx context.Context) error
	Start(ctx context.Context) error
}

// Usage is what a move needs to know of a filesystem.
type Usage struct {
	// Avail is the room an unprivileged writer may still use.
	Avail uint64
	// Device identifies the filesystem, so two paths on one volume count
	// once.
	Device uint64
}

// Move is one data move on the box.
type Move struct {
	Spec productspec.DataMove
	// Slot is the product slot whose bundle holds the checks.
	Slot string
	// BackupDir is the backup partition's directory for moves; the dump
	// goes in a directory of its own in it.
	BackupDir string
	// Journal is the file that records how far the move got. It lives on
	// the state volume and outlives a crash or a power loss.
	Journal string
	// Volumes is the directory the target's volume grows in.
	Volumes  string
	Engine   Engine
	Services Services
	// Disk reads the filesystem a path is on.
	Disk func(string) (Usage, error)
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Progress hears what the move is doing, for the update's step.
	Progress func(string)
	// Audit hears what the OS audit log records of a move; nil records
	// nothing.
	Audit func(action string, detail map[string]string)
	// Remove takes a dump away; nil is os.RemoveAll.
	Remove func(string) error
	Logger log.Logger
}

func (m *Move) logger() log.Logger {
	if m.Logger == nil {
		return log.Nop()
	}
	return m.Logger
}

func (m *Move) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Move) say(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	m.logger().Info("datamove: "+s, log.F("source", m.Spec.Source.Name), log.F("target", m.Spec.Target.Name))
	if m.Progress != nil {
		m.Progress(s)
	}
}

func (m *Move) audit(action string, detail map[string]string) {
	if m.Audit != nil {
		m.Audit(action, detail)
	}
}

func (m *Move) dumpDir() string { return filepath.Join(m.BackupDir, "dump") }

// Run moves the data, or does nothing when it has moved already. Any error
// means the source is as it was and the services never started on the
// target; the caller takes the box back to its previous product slot.
func (m *Move) Run(ctx context.Context) error {
	j, err := m.Read()
	if err != nil {
		return codes.Wrap(codes.DataMove, err)
	}
	switch j.State {
	case StateSwitched, StateDone:
		m.logger().Debug("datamove: already moved", log.F("state", string(j.State)))
		return nil
	case StateRunning:
		m.logger().Warn("datamove: an earlier run was cut off", log.F("step", string(j.Step)), log.F("attempt", j.Attempt))
		j.State, j.Reason = StateFailed, fmt.Sprintf("the move was cut off during %s", j.Step)
		if err := m.save(j); err != nil {
			return codes.Wrap(codes.DataMove, err)
		}
		return codes.Wrap(codes.DataMove, fmt.Errorf("%w during %s", ErrInterrupted, j.Step))
	}
	if ctx.Err() != nil {
		return codes.Wrap(codes.DataMove, ctx.Err())
	}
	j.State, j.Step, j.Reason, j.Started, j.Finished, j.Nothing = StateRunning, StepPrepare, "", m.now(), time.Time{}, false
	j.Target = m.Spec.Target.Name
	j.Attempt++
	if err := m.save(j); err != nil {
		return codes.Wrap(codes.DataMove, err)
	}
	if j.Returning {
		m.audit(ActionReturn, map[string]string{"attempt": strconv.Itoa(j.Attempt), "target": j.Target})
	}
	ctx, cancel := context.WithTimeout(ctx, m.Spec.TimeoutOrDefault())
	defer cancel()
	m.logger().Info("datamove: starting", log.F("attempt", j.Attempt), log.F("databases", len(m.Spec.Databases)), log.F("target_host", m.Spec.Target.Host), log.F("sslmode", m.Spec.Target.SSLModeOrDefault()))
	err = m.steps(ctx, j)
	if err != nil {
		m.logger().Error(err, "datamove: failed; the old cluster is as it was", log.F("step", string(j.Step)))
		j.State, j.Reason, j.Finished = StateFailed, fmt.Sprintf("%s: %s", j.Step, err.Error()), m.now()
		if serr := m.save(j); serr != nil {
			err = errors.Join(err, serr)
		}
		if codes.Is(err, codes.DataMoveRoom) {
			return err
		}
		return codes.Wrap(codes.DataMove, fmt.Errorf("%s: %w", j.Step, err))
	}
	m.logger().Info("datamove: finished", log.F("state", string(j.State)), log.F("seconds", int(m.now().Sub(j.Started).Seconds())))
	return nil
}

func (m *Move) step(j *Journal, s Step) error {
	j.Step = s
	m.logger().Debug("datamove: step", log.F("step", string(s)))
	return m.save(j)
}

func (m *Move) steps(ctx context.Context, j *Journal) error {
	src, tgt := m.Spec.Source, m.Spec.Target
	checks, err := m.readChecks()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.BackupDir, 0o700); err != nil {
		return fmt.Errorf("making the move's directory: %w", err)
	}
	m.say("Checking the database")
	if err := m.Engine.WaitReady(ctx, src); err != nil {
		return fmt.Errorf("the old database: %w", err)
	}
	if j.Returning {
		m.say("Moving the old database again, because the box went back to it")
		if err := m.dropPartial(j); err != nil {
			return err
		}
	}
	if err := m.room(ctx, j); err != nil {
		return err
	}
	empty, err := m.sourceEmpty(ctx)
	if err != nil {
		return err
	}
	if empty {
		m.logger().Info("datamove: the old databases hold no tables; nothing to move")
		j.State, j.Nothing, j.Returning, j.Finished = StateDone, true, false, m.now()
		return m.save(j)
	}
	if err := m.step(j, StepStop); err != nil {
		return err
	}
	m.say("Stopping the services")
	if err := m.Services.Stop(ctx); err != nil {
		return fmt.Errorf("stopping the services: %w", err)
	}
	if err := m.step(j, StepDump); err != nil {
		return err
	}
	man, err := m.dump(ctx)
	if err != nil {
		return err
	}
	if err := m.step(j, StepTarget); err != nil {
		return err
	}
	m.say("Starting the new database")
	if err := m.Engine.WaitReady(ctx, tgt); err != nil {
		return fmt.Errorf("the new database: %w", err)
	}
	full, err := m.clearable(ctx, j)
	if err != nil {
		return err
	}
	if err := m.keep(ctx, j, full); err != nil {
		return err
	}
	// On disk before the first write: a move cut off mid-restore has to
	// know the partial data is its own.
	j.TargetTouched = true
	if err := m.step(j, StepRestore); err != nil {
		return err
	}
	if err := m.restore(ctx, j, man); err != nil {
		return err
	}
	if err := m.step(j, StepCheck); err != nil {
		return err
	}
	for _, c := range checks {
		m.say("Checking %s", c.name)
		out, err := m.Engine.Check(ctx, tgt, c.database, c.query)
		if err != nil {
			return fmt.Errorf("the check %s: %w", c.name, err)
		}
		if strings.TrimSpace(out) != "ok" {
			return fmt.Errorf("the check %s: %s", c.name, strings.TrimSpace(out))
		}
	}
	if err := m.step(j, StepStart); err != nil {
		return err
	}
	// Past here the services run on the target, so the switch is recorded
	// first: a cut-off start doesn't move the data a second time.
	m.say("Starting the services")
	j.State = StateSwitched
	if err := m.save(j); err != nil {
		return err
	}
	if err := m.Services.Start(ctx); err != nil {
		return fmt.Errorf("starting the services: %w", err)
	}
	return nil
}

type check struct {
	name, database string
	query          []byte
}

func (m *Move) readChecks() ([]check, error) {
	out := make([]check, 0, len(m.Spec.Checks))
	for _, c := range m.Spec.Checks {
		b, err := os.ReadFile(filepath.Join(m.Slot, c.File)) // #nosec G304 -- a file of the installed slot, named by its signed product.yaml
		if err != nil {
			return nil, fmt.Errorf("the check %s: %w", c.Name, err)
		}
		out = append(out, check{c.Name, c.Database, b})
	}
	return out, nil
}

func (m *Move) sourceEmpty(ctx context.Context) (bool, error) {
	for _, db := range m.Spec.Databases {
		n, err := m.Engine.Tables(ctx, m.Spec.Source, db)
		if err != nil {
			return false, err
		}
		if n > 0 {
			return false, nil
		}
	}
	return true, nil
}

// clearable refuses a target that holds tables this move didn't put there:
// a move only ever drops what an earlier attempt of its own wrote. It
// answers the databases that hold tables.
func (m *Move) clearable(ctx context.Context, j *Journal) ([]string, error) {
	var full []string
	for _, db := range m.Spec.Databases {
		n, err := m.Engine.Tables(ctx, m.Spec.Target, db)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			full = append(full, db)
		}
	}
	if len(full) > 0 && !j.TargetTouched {
		return nil, fmt.Errorf("the new database already holds %s, and this move didn't put it there", strings.Join(full, ", "))
	}
	if len(full) > 0 {
		m.logger().Info("datamove: clearing an earlier attempt from the new database", log.F("databases", strings.Join(full, ",")))
	}
	return full, nil
}

func (m *Move) restore(ctx context.Context, j *Journal, man *manifest) error {
	tgt := m.Spec.Target
	if err := m.verifyDump(m.dumpDir(), man); err != nil {
		return err
	}
	m.say("Restoring the roles")
	if err := m.fromFile(man.Roles, func(r io.Reader) error { return m.Engine.RestoreRoles(ctx, tgt, r) }); err != nil {
		return fmt.Errorf("restoring the roles: %w", err)
	}
	for i, db := range man.Databases {
		m.say("Restoring %s (%d of %d)", db.Name, i+1, len(man.Databases))
		if err := m.Engine.DropDatabase(ctx, tgt, db.Name); err != nil {
			return fmt.Errorf("clearing %s: %w", db.Name, err)
		}
		if err := m.fromFile(db.Part, func(r io.Reader) error { return m.Engine.RestoreDatabase(ctx, tgt, db.Name, r) }); err != nil {
			return fmt.Errorf("restoring %s: %w", db.Name, err)
		}
		got, err := m.Engine.Counts(ctx, tgt, db.Name)
		if err != nil {
			return fmt.Errorf("counting %s: %w", db.Name, err)
		}
		if diff := compareRows(db.Rows, got); diff != "" {
			return fmt.Errorf("%s doesn't match its dump: %s", db.Name, diff)
		}
		m.logger().Info("datamove: every table matches", log.F("database", db.Name), log.F("tables", len(got)))
	}
	return nil
}

func (m *Move) fromFile(p Part, use func(io.Reader) error) error {
	f, err := os.Open(filepath.Join(m.dumpDir(), p.File)) // #nosec G304 -- the move's own dump
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return use(f)
}

// compareRows says how got differs from want, by table, or "".
func compareRows(want, got map[string]int64) string {
	var diff []string
	names := slices.Sorted(maps.Keys(want))
	for _, t := range names {
		n, ok := got[t]
		switch {
		case !ok:
			diff = append(diff, t+" is missing")
		case n != want[t]:
			diff = append(diff, fmt.Sprintf("%s has %d rows, not %d", t, n, want[t]))
		}
	}
	for _, t := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[t]; !ok {
			diff = append(diff, t+" isn't in the dump")
		}
	}
	return strings.Join(diff, "; ")
}

// Settle records that the box came up healthy on the target. A failed move
// isn't settled.
func (m *Move) Settle() error {
	j, err := m.Read()
	if err != nil {
		return err
	}
	switch j.State {
	case StateDone:
		return nil
	case StateSwitched:
		j.State, j.Returning, j.Finished = StateDone, false, m.now()
		m.logger().Info("datamove: settled; the box is healthy on the new database")
		if err := m.save(j); err != nil {
			return err
		}
		m.removeDump(j)
		return nil
	}
	return fmt.Errorf("datamove: a move in state %q can't settle", j.State)
}

// Fail records that the box didn't come up on a move that had switched, so
// it goes back to the old cluster and a later apply moves the data again.
// A settled move stays settled.
func (m *Move) Fail(why string) error {
	j, err := m.Read()
	if err != nil {
		return err
	}
	if j.State == StateDone || j.State == StateFailed {
		return nil
	}
	j.State, j.Reason, j.Finished = StateFailed, why, m.now()
	return m.save(j)
}
