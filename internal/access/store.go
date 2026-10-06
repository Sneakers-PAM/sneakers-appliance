// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package access

import (
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
)

// FileName is the store's file inside its directory.
const FileName = "store.json"

// State is the whole access store (spec 2, Section 4.1).
type State struct {
	Version         int           `json:"version"`
	NextUID         int           `json:"nextUid"`
	Admins          []Admin       `json:"admins"`
	RecoveryKeys    []RecoveryKey `json:"recoveryKeys"`
	ElevationPolicy Policy        `json:"elevationPolicy"`
}

// Clone returns a deep copy of s.
func (s State) Clone() State {
	c := s
	c.Admins = make([]Admin, len(s.Admins))
	for i, a := range s.Admins {
		a.Keys = slices.Clone(a.Keys)
		for j, k := range a.Keys {
			if k.LastUsed != nil {
				t := *k.LastUsed
				a.Keys[j].LastUsed = &t
			}
		}
		if a.ApprovalHoldUntil != nil {
			t := *a.ApprovalHoldUntil
			a.ApprovalHoldUntil = &t
		}
		c.Admins[i] = a
	}
	c.RecoveryKeys = slices.Clone(s.RecoveryKeys)
	return c
}

// Admin returns the admin named name.
func (s *State) Admin(name string) (*Admin, bool) {
	for i := range s.Admins {
		if s.Admins[i].Name == name {
			return &s.Admins[i], true
		}
	}
	return nil, false
}

// AdminByUID returns the admin with uid.
func (s *State) AdminByUID(uid int) (*Admin, bool) {
	for i := range s.Admins {
		if s.Admins[i].UID == uid {
			return &s.Admins[i], true
		}
	}
	return nil, false
}

// AddAdmin appends an admin with the next free uid and returns it. Check
// (run by Update) refuses an invalid or taken name.
func (s *State) AddAdmin(name string, role Role, createdBy string, now time.Time) *Admin {
	if s.NextUID < FirstUID {
		s.NextUID = FirstUID
	}
	s.Admins = append(s.Admins, Admin{Name: name, UID: s.NextUID, Role: role, Created: now.UTC(), CreatedBy: createdBy, Keys: []AdminKey{}})
	s.NextUID++
	return &s.Admins[len(s.Admins)-1]
}

// Stage reports which setup steps have completed, so Check knows whether an
// empty admin or recovery key list is still allowed.
type Stage func() (adminDone, recoveryDone bool)

// Done is the Stage of a box past setup: every invariant applies.
func Done() (bool, bool) { return true, true }

// Store is the access store on disk. Every write goes through Update, which
// serializes writers, checks the invariants and replaces the file
// atomically.
type Store struct {
	dir string
	o   Options
	mu  sync.Mutex
	cur State
}

// Options tune a store.
type Options struct {
	// Stage reports the setup progress; nil applies every invariant.
	Stage  Stage
	Logger log.Logger
}

// Open opens (or starts) the store in dir.
func Open(dir string, o Options) (*Store, error) {
	if o.Stage == nil {
		o.Stage = Done
	}
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("access store: %w", err)
	}
	// A leftover tmp file is a write that never reached its rename; the
	// previous version is still the store.
	if err := os.Remove(filepath.Join(dir, FileName+".tmp")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("access store: %w", err)
	}
	s := &Store{dir: dir, o: o}
	cur, err := s.load()
	if err != nil {
		return nil, err
	}
	s.cur = cur
	return s, nil
}

// Read returns a copy of the current state.
func (s *Store) Read() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur.Clone()
}

// Update applies fn to a copy of the newest state on disk, checks the
// invariants and, when both pass, writes the result as the next version.
// Concurrent Updates run one after the other, each on the state the last one
// left, so no interleaving can break an invariant.
func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.load()
	if err != nil {
		return err
	}
	next := cur.Clone()
	if err := fn(&next); err != nil {
		return err
	}
	adminDone, recoveryDone := s.o.Stage()
	if err := Check(next, adminDone, recoveryDone); err != nil {
		s.o.Logger.Warn("access: change refused", log.F("version", cur.Version), log.F("error", codes.Describe(err)))
		return err
	}
	next.Version = cur.Version + 1
	if err := s.write(next); err != nil {
		s.o.Logger.Error(err, "access: store write failed", log.F("version", next.Version))
		return err
	}
	s.cur = next
	s.o.Logger.Info("access: store updated", log.F("version", next.Version), log.F("admins", len(next.Admins)), log.F("recoveryKeys", len(next.RecoveryKeys)))
	return nil
}

func (s *Store) path() string { return filepath.Join(s.dir, FileName) }

func (s *Store) load() (State, error) {
	b, err := os.ReadFile(s.path())
	if errors.Is(err, fs.ErrNotExist) {
		return State{NextUID: FirstUID, Admins: []Admin{}, RecoveryKeys: []RecoveryKey{}, ElevationPolicy: DefaultPolicy()}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("access store: %w", err)
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, codes.Wrap(codes.AccessStoreInvalid, fmt.Errorf("%s doesn't parse: %w", s.path(), err))
	}
	return st, nil
}

func (s *Store) write(st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("access store: %w", err)
	}
	tmp := s.path() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the store directory accessd was given
	if err != nil {
		return fmt.Errorf("access store: %w", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("access store: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("access store: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("access store: %w", err)
	}
	if err := os.Rename(tmp, s.path()); err != nil {
		return fmt.Errorf("access store: %w", err)
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return fmt.Errorf("access store: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("access store: %w", err)
	}
	return nil
}
