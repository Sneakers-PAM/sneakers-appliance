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
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// JournalFile is the restore's journal, in the platform settings directory.
const JournalFile = "backup-restore.json"

// asideSuffix marks what a restore moved aside, on the same volume, so going
// back is a rename.
const asideSuffix = ".pre-restore"

const (
	restoreBound = 6 * time.Hour
	// settleBound is how long the product has to come up on the restored
	// data before the box goes back.
	settleBound = 30 * time.Minute
	// walRoom is the write-ahead log a restore may hold on top of the
	// restored data.
	walRoom = 1 << 30
)

// State is where a restore stands.
type State string

// The states of a restore.
const (
	StateRequested State = "requested"
	StateRunning   State = "running"
	// StateSettling: the cluster is restored and checked, and the product
	// is coming up on it. What was moved aside stays until it's ready.
	StateSettling State = "settling"
	// StateGoingBack: the restore failed, and the box is on its way back.
	StateGoingBack State = "going-back"
	StateDone      State = "done"
	StateFailed    State = "failed"
)

// Journal is the restore's record, synced before every step, so a power loss
// can't lose where it stood.
type Journal struct {
	State    State     `json:"state"`
	Set      string    `json:"set"`
	Point    string    `json:"point"`
	Actor    string    `json:"actor,omitempty"`
	Step     string    `json:"step,omitempty"`
	Started  time.Time `json:"started,omitzero"`
	Deadline time.Time `json:"deadline,omitzero"`
	Finished time.Time `json:"finished,omitzero"`
	Why      string    `json:"why,omitempty"`
}

func (j Journal) active() bool {
	return slices.Contains([]State{StateRequested, StateRunning, StateSettling, StateGoingBack}, j.State)
}

// Kube is what a restore does to the cluster's workload. The box's is
// Cluster.
type Kube interface {
	// Stop scales the cluster to 0 and waits for its pod to go; Start
	// scales it to one.
	Stop(ctx context.Context, b productspec.Backups) error
	Start(ctx context.Context, b productspec.Backups) error
	SetEnv(ctx context.Context, b productspec.Backups, env map[string]string) error
	// UnsetEnv removes the restore's variables. A workload that isn't
	// there isn't an error: the phase loop places it as declared.
	UnsetEnv(ctx context.Context, b productspec.Backups, names []string) error
	// ClearIdentity removes the annotations that tie the cluster to the
	// data moved aside.
	ClearIdentity(ctx context.Context, b productspec.Backups) error
	// WaitPrimary waits until the cluster answers and takes writes.
	WaitPrimary(ctx context.Context, b productspec.Backups) error
	// Check runs one check in database and answers what it printed.
	Check(ctx context.Context, b productspec.Backups, db string, sql []byte) (string, error)
}

// Services stops what uses the database.
type Services interface {
	Stop(ctx context.Context) error
}

// Status is what the phase loop asks of a restore.
type Status struct {
	// Busy: a restore holds the product, and the loop waits.
	Busy   bool
	Detail string
}

// Restorer runs one restore at a time, behind the phase loop.
type Restorer struct {
	Spec   func() (productspec.Spec, error)
	Engine Engine
	Kube   Kube
	// Slot is the installed slot, holding the checks' files.
	Slot string
	// Journal is the journal's path.
	Journal string
	// DataRoot is productspec.DataRoot unless a rehearsal says otherwise.
	DataRoot string
	// Avail answers the room left on the volume holding a path.
	Avail  func(p string) (uint64, error)
	Audit  func(action string, detail map[string]string)
	Logger log.Logger
	Now    func() time.Time
	// OnStep, when set, hears each step once its journal is on disk: the
	// rehearsal kills the process there.
	OnStep func(string)

	mu      sync.Mutex
	running bool
	detail  string
}

func (r *Restorer) logger() log.Logger {
	if r.Logger == nil {
		return log.Nop()
	}
	return r.Logger
}

func (r *Restorer) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *Restorer) audit(action string, detail map[string]string) {
	if r.Audit != nil {
		r.Audit(action, detail)
	}
}

// Read reads the journal; a missing one is the zero journal.
func (r *Restorer) Read() (Journal, error) {
	var j Journal
	b, err := os.ReadFile(r.Journal)
	if errors.Is(err, fs.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		return j, err
	}
	return j, json.Unmarshal(b, &j)
}

func (r *Restorer) save(j Journal) error {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.Journal + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the box's own journal
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
		return err
	}
	if err := os.Rename(tmp, r.Journal); err != nil {
		return err
	}
	return syncDir(filepath.Dir(r.Journal))
}

// Active is whether a restore holds the product.
func (r *Restorer) Active() bool {
	j, err := r.Read()
	return err == nil && j.active()
}

func (r *Restorer) pgdata(s productspec.Spec) (string, error) {
	d, ok := s.BackupData()
	if !ok {
		return "", codes.New(codes.BackupSet, "the installed product declares no data path for its backups")
	}
	root := r.DataRoot
	if root == "" {
		root = productspec.DataRoot
	}
	return filepath.Join(root, d.Path, s.Backups.PGData), nil
}

// Request checks a restore can go ahead and records it; the phase loop then
// runs it. Everything that can refuse it refuses here, before the product
// stops, and a refusal changes nothing.
func (r *Restorer) Request(ctx context.Context, set, actor string) error {
	s, err := r.Spec()
	if err != nil {
		return err
	}
	if s.Backups == nil {
		return codes.New(codes.BackupSet, "the installed product declares no backups")
	}
	b := *s.Backups
	if j, err := r.Read(); err != nil {
		return codes.Wrap(codes.Backup, err)
	} else if j.active() {
		return codes.New(codes.BackupBusy, "a restore of %s is under way", j.Set)
	}
	mf, err := ReadManifest(b, set)
	if err != nil {
		return err
	}
	for _, k := range s.Escrow {
		d, err := r.Engine.KeyDigest(ctx, k)
		if err != nil {
			return codes.New(codes.Backup, "the product key %s doesn't read: %v", k.Name, err)
		}
		if want, ok := mf.Keys[k.Name]; !ok || want != d {
			return codes.New(codes.BackupOtherBox, "the set %s was made on a box holding another %s, so its data can't be opened here. Restoring onto a different box isn't supported yet; nothing changed", set, k.Name)
		}
	}
	data, err := r.pgdata(s)
	if err != nil {
		return err
	}
	if r.Avail != nil {
		need := uint64(max(mf.Uncompressed, 0)) + walRoom // #nosec G115 -- held at 0 or more
		have, err := r.Avail(filepath.Dir(data))
		if err != nil {
			return codes.Wrap(codes.Backup, err)
		}
		if have < need {
			return codes.New(codes.BackupRoom, "the restore needs %d MiB on the data volume beside the data it keeps, and there's %d MiB free; nothing changed", need>>20, have>>20)
		}
	}
	if err := r.save(Journal{State: StateRequested, Set: set, Point: mf.Point, Actor: actor, Started: r.now()}); err != nil {
		return codes.Wrap(codes.Backup, err)
	}
	r.logger().Info("backupset: a restore is requested", log.F("set", set), log.F("by", actor))
	r.audit("product.backup.restore.start", map[string]string{"set": set, "point": mf.Point})
	return nil
}

// Ask moves a restore on and says whether it holds the product. The loop asks
// every few seconds, so a restore cut off by a restart or a power loss is
// found here and goes back.
func (r *Restorer) Ask(svc Services) Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		return Status{Busy: true, Detail: r.detail}
	}
	j, err := r.Read()
	if err != nil {
		r.logger().Error(err, "backupset: the restore's journal doesn't read; the product waits")
		return Status{Busy: true, Detail: "The restore's journal doesn't read."}
	}
	if !j.active() {
		return Status{}
	}
	switch j.State {
	case StateSettling:
		if r.now().Before(j.Deadline) {
			return Status{}
		}
		j.Why = "the product didn't come up on the restored data in time"
		r.start(func() { r.goBack(j, svc) })
	case StateRunning:
		j.Why = "the restore was cut off"
		r.start(func() { r.goBack(j, svc) })
	case StateGoingBack:
		r.start(func() { r.goBack(j, svc) })
	default:
		r.start(func() { r.run(j, svc) })
	}
	return Status{Busy: true, Detail: r.detail}
}

// start runs f behind the loop. r.mu is held.
func (r *Restorer) start(f func()) {
	r.running, r.detail = true, "Starting the restore"
	go func() {
		defer func() {
			r.mu.Lock()
			r.running = false
			r.mu.Unlock()
		}()
		f()
	}()
}

func (r *Restorer) progress(s string) {
	r.mu.Lock()
	r.detail = s
	r.mu.Unlock()
}

// step records the step, so a cut-off restore says where it stopped.
func (r *Restorer) step(j *Journal, name, words string) error {
	j.Step = name
	r.progress(words)
	r.logger().Info("backupset: restore step", log.F("set", j.Set), log.F("step", name))
	if err := r.save(*j); err != nil {
		return err
	}
	if r.OnStep != nil {
		r.OnStep(name)
	}
	return nil
}

func (r *Restorer) run(j Journal, svc Services) {
	ctx, cancel := context.WithTimeout(context.Background(), restoreBound)
	defer cancel()
	j.State = StateRunning
	if err := r.restore(ctx, &j, svc); err != nil {
		r.logger().Warn("backupset: the restore failed; going back", log.F("set", j.Set), log.F("step", j.Step), log.F("error", err.Error()))
		j.Why = fmt.Sprintf("%s: %v", j.Step, err)
		r.goBack(j, svc)
		return
	}
	j.State, j.Step, j.Deadline = StateSettling, "", r.now().Add(settleBound)
	if err := r.save(j); err != nil {
		r.logger().Error(err, "backupset: the restore's journal wasn't written; the next ask goes back")
	}
}

func (r *Restorer) restore(ctx context.Context, j *Journal, svc Services) error {
	s, err := r.Spec()
	if err != nil {
		return err
	}
	if s.Backups == nil {
		return errors.New("the installed product declares no backups")
	}
	b := *s.Backups
	if err := r.step(j, "verify", "Checking the backup set"); err != nil {
		return err
	}
	mf, err := ReadManifest(b, j.Set)
	if err != nil {
		return err
	}
	if err := Verify(b, mf); err != nil {
		return err
	}
	if err := r.step(j, "stop", "Stopping the services"); err != nil {
		return err
	}
	if err := svc.Stop(ctx); err != nil {
		return err
	}
	if err := r.Kube.Stop(ctx, b); err != nil {
		return err
	}
	data, err := r.pgdata(s)
	if err != nil {
		return err
	}
	if err := r.step(j, "aside", "Keeping the data the box has"); err != nil {
		return err
	}
	for _, p := range []string{data, b.StoreHostDir()} {
		if err := os.Rename(p, p+asideSuffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := syncDir(filepath.Dir(p)); err != nil {
			return err
		}
	}
	if err := r.step(j, "restore", "Restoring the database to "+j.Point); err != nil {
		return err
	}
	if err := r.Kube.ClearIdentity(ctx, b); err != nil {
		return err
	}
	if err := r.Kube.SetEnv(ctx, b, b.RestoreEnv(j.Set, j.Point)); err != nil {
		return err
	}
	if err := r.Kube.Start(ctx, b); err != nil {
		return err
	}
	if err := r.Kube.WaitPrimary(ctx, b); err != nil {
		return err
	}
	if err := r.step(j, "check", "Checking the restored data"); err != nil {
		return err
	}
	for _, c := range b.Checks {
		sql, err := os.ReadFile(filepath.Join(r.Slot, filepath.FromSlash(c.File))) // #nosec G304 -- a path productspec checked, in the box's own slot
		if err != nil {
			return err
		}
		got, err := r.Kube.Check(ctx, b, c.Database, sql)
		if err != nil {
			return fmt.Errorf("%s: %w", c.Name, err)
		}
		if got != "ok" {
			return fmt.Errorf("%s: %s", c.Name, got)
		}
	}
	if err := r.step(j, "finish", "Starting the database"); err != nil {
		return err
	}
	if err := r.Kube.Stop(ctx, b); err != nil {
		return err
	}
	return r.Kube.UnsetEnv(ctx, b, envNames(b))
}

func envNames(b productspec.Backups) []string {
	out := make([]string, 0, len(b.Restore.Env))
	for k := range b.Restore.Env {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// goBack returns the box to the data it had. Every step can run twice: the
// journal stays going-back until the last is done, and the next ask carries on.
func (r *Restorer) goBack(j Journal, svc Services) {
	j.State = StateGoingBack
	r.progress("Going back to the data the box had")
	if err := r.save(j); err != nil {
		r.logger().Error(err, "backupset: the restore's journal wasn't written")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), restoreBound)
	defer cancel()
	if err := r.back(ctx, svc); err != nil {
		r.logger().Error(err, "backupset: going back didn't finish; the next ask tries again")
		time.Sleep(time.Second)
		return
	}
	j.State, j.Finished = StateFailed, r.now()
	if err := r.save(j); err != nil {
		r.logger().Error(err, "backupset: the restore's journal wasn't written")
		return
	}
	r.logger().Warn("backupset: the restore failed and the box is back on its data", log.F("set", j.Set), log.F("why", j.Why))
	r.audit("product.backup.restore.failed", map[string]string{"set": j.Set, "point": j.Point, "why": j.Why})
}

func (r *Restorer) back(ctx context.Context, svc Services) error {
	s, err := r.Spec()
	if err != nil {
		return err
	}
	if s.Backups == nil {
		return errors.New("the installed product declares no backups")
	}
	b := *s.Backups
	if err := svc.Stop(ctx); err != nil {
		return err
	}
	if err := r.Kube.Stop(ctx, b); err != nil {
		return err
	}
	if err := r.Kube.UnsetEnv(ctx, b, envNames(b)); err != nil {
		return err
	}
	data, err := r.pgdata(s)
	if err != nil {
		return err
	}
	for _, p := range []string{data, b.StoreHostDir()} {
		if _, err := os.Stat(p + asideSuffix); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := os.RemoveAll(p); err != nil {
			return err
		}
		if err := os.Rename(p+asideSuffix, p); err != nil {
			return err
		}
		if err := syncDir(filepath.Dir(p)); err != nil {
			return err
		}
	}
	return nil
}

// Settle records the product healthy on the restored data: what was moved
// aside goes, and the cluster takes a first base backup in its new archive.
func (r *Restorer) Settle(ctx context.Context) error {
	j, err := r.Read()
	if err != nil {
		return err
	}
	if j.State != StateSettling {
		return nil
	}
	s, err := r.Spec()
	if err != nil {
		return err
	}
	if s.Backups == nil {
		return errors.New("the installed product declares no backups")
	}
	b := *s.Backups
	data, err := r.pgdata(s)
	if err != nil {
		return err
	}
	j.State, j.Finished = StateDone, r.now()
	if err := r.save(j); err != nil {
		return err
	}
	for _, p := range []string{data, b.StoreHostDir()} {
		if err := os.RemoveAll(p + asideSuffix); err != nil {
			r.logger().Warn("backupset: what the restore moved aside wasn't removed", log.F("path", p+asideSuffix), log.F("error", err.Error()))
		}
	}
	if err := r.Engine.RequestBase(ctx, b); err != nil {
		r.logger().Warn("backupset: the first base backup after the restore wasn't asked for; the schedule takes one", log.F("error", err.Error()))
	}
	r.logger().Info("backupset: the box is healthy on the restored data", log.F("set", j.Set))
	r.audit("product.backup.restore.done", map[string]string{"set": j.Set, "point": j.Point})
	return nil
}
