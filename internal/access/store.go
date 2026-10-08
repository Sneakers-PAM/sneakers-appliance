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
	Version      int           `json:"version"`
	NextUID      int           `json:"nextUid"`
	Admins       []Admin       `json:"admins"`
	RecoveryKeys []RecoveryKey `json:"recoveryKeys"`
	AccessPolicy Policy        `json:"accessPolicy"`
	// Quorum is the root-operator roster, which also approves a factory
	// reset; nil (a store from before the first admin set it) means every
	// admin, two approvals.
	Quorum *QuorumRoster `json:"quorum,omitempty"`
	// RevokedKeys are removed login keys, on sshd's revocation list.
	RevokedKeys []RevokedKey `json:"revokedKeys,omitempty"`
	// NextSerial is the next issued certificate's serial.
	NextSerial uint64 `json:"nextSerial,omitempty"`
	// LastRecoverAccess is the last console Recover access, shown to every
	// admin at their next sign-in.
	LastRecoverAccess *time.Time `json:"lastRecoverAccess,omitempty"`
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
		for j, k := range a.Keys {
			if k.ValidBefore != nil {
				t := *k.ValidBefore
				a.Keys[j].ValidBefore = &t
			}
		}
		if a.Password != nil {
			p := *a.Password
			a.Password = &p
		}
		if a.TOTP != nil {
			p := *a.TOTP
			a.TOTP = &p
		}
		if a.Invite != nil {
			p := *a.Invite
			a.Invite = &p
		}
		if a.LastSignIn != nil {
			t := *a.LastSignIn
			a.LastSignIn = &t
		}
		c.Admins[i] = a
	}
	c.RecoveryKeys = slices.Clone(s.RecoveryKeys)
	c.Quorum = s.Quorum.clone()
	c.RevokedKeys = slices.Clone(s.RevokedKeys)
	if s.LastRecoverAccess != nil {
		t := *s.LastRecoverAccess
		c.LastRecoverAccess = &t
	}
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
// empty admin or recovery key list is still allowed: the admin step is done
// once the first admin exists, the recovery step once setup is done.
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
	// OnChange, when set, gets every version Update writes, after the
	// write and outside the store's lock.
	OnChange func(State)
	// Revoke, when set, writes sshd's revocation list from a version about
	// to be written, inside the store's lock: an error refuses the change,
	// so a removed key is never out of the store and still accepted. Open
	// calls it with the stored version.
	Revoke func(State) error
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
	if o.Revoke != nil {
		if err := o.Revoke(cur.Clone()); err != nil {
			return nil, fmt.Errorf("access store: revocation list: %w", err)
		}
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
// left, so no interleaving can break an invariant. A key the change removes
// is revoked with no actor recorded; a call made for someone uses UpdateAs.
func (s *Store) Update(fn func(*State) error) error { return s.UpdateAs("", fn) }

// UpdateAs is Update made by by, an admin's name or ConsoleActor: the keys
// the change removes are revoked as by's.
func (s *Store) UpdateAs(by string, fn func(*State) error) error {
	next, err := s.update(by, fn)
	if err == nil && s.o.OnChange != nil {
		s.o.OnChange(next.Clone())
	}
	return err
}

func (s *Store) update(by string, fn func(*State) error) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.load()
	if err != nil {
		return State{}, err
	}
	next := cur.Clone()
	if err := fn(&next); err != nil {
		return State{}, err
	}
	revokeRemoved(cur, &next, time.Now(), by)
	adminDone, recoveryDone := s.o.Stage()
	if err := Check(next, adminDone, recoveryDone); err != nil {
		s.o.Logger.Warn("access: change refused", log.F("version", cur.Version), log.F("error", codes.Describe(err)))
		return State{}, err
	}
	next.Version = cur.Version + 1
	if s.o.Revoke != nil {
		if err := s.o.Revoke(next.Clone()); err != nil {
			s.o.Logger.Error(err, "access: revocation list not written; change refused", log.F("version", next.Version))
			return State{}, fmt.Errorf("access store: revocation list: %w", err)
		}
	}
	if err := s.write(next); err != nil {
		s.o.Logger.Error(err, "access: store write failed", log.F("version", next.Version))
		if s.o.Revoke != nil {
			// Back to the list of the version still on disk.
			if rerr := s.o.Revoke(cur.Clone()); rerr != nil {
				s.o.Logger.Error(rerr, "access: revocation list not restored", log.F("version", cur.Version))
			}
		}
		return State{}, err
	}
	if n := len(next.RevokedKeys) - len(cur.RevokedKeys); n > 0 {
		s.o.Logger.Info("access: login keys revoked", log.F("version", next.Version), log.F("keys", n), log.F("by", by))
	}
	s.cur = next
	s.o.Logger.Info("access: store updated", log.F("version", next.Version), log.F("admins", len(next.Admins)), log.F("recoveryKeys", len(next.RecoveryKeys)))
	return next, nil
}

func (s *Store) path() string { return filepath.Join(s.dir, FileName) }

func (s *Store) load() (State, error) { return ReadState(s.dir) }

// ReadState reads the store in dir without opening it for writing: init
// checks a factory reset's quorum this way, beside the store's writer.
func ReadState(dir string) (State, error) {
	p := filepath.Join(dir, FileName)
	b, err := os.ReadFile(p) // #nosec G304 -- the store file in the directory given
	if errors.Is(err, fs.ErrNotExist) {
		return State{NextUID: FirstUID, Admins: []Admin{}, RecoveryKeys: []RecoveryKey{}, AccessPolicy: DefaultPolicy(), NextSerial: 1}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("access store: %w", err)
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, codes.Wrap(codes.AccessStoreInvalid, fmt.Errorf("%s doesn't parse: %w", p, err))
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
