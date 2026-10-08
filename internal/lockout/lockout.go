// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package lockout is the sign-in lockout and throttling every surface
// shares (spec 2, Section 2.6): :8443 sign-in and step-up, the closed
// shell's TOTP check, the root-shell code page and the one-time codes.
// Per account (NIST SP 800-53 AC-7, the DoD SRG and STIG values): 3
// consecutive failures within 15 minutes lock it for 15 minutes, or until
// an owner unlocks it. Per source (NIST SP 800-63B rate limiting): 10
// failures within 15 minutes, whatever names were tried, hold that address
// off for 15 minutes. The book also keeps each admin's last TOTP step, so
// a code is never taken twice. It is kept on the state volume, so a restart
// doesn't clear a lock.
package lockout

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

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// The limits.
const (
	MaxFailures  = 3
	Window       = 15 * time.Minute
	LockFor      = 15 * time.Minute
	SourceMax    = 10
	SourceWindow = 15 * time.Minute
	SourceHold   = 15 * time.Minute
)

// Mode is what a lock lasts for.
type Mode string

// The modes.
const (
	// Timed locks for LockFor.
	Timed Mode = "timed"
	// UntilUnlocked locks until an owner unlocks.
	UntilUnlocked Mode = "until-unlocked"
)

// Refusal is what a refused try tells the caller.
type Refusal struct {
	AttemptsLeft  int
	LockedUntil   time.Time
	UntilUnlocked bool
	RetryAfter    time.Time
}

type refusalError struct {
	err error
	r   Refusal
}

func (e *refusalError) Error() string { return e.err.Error() }
func (e *refusalError) Unwrap() error { return e.err }

// RefusalOf returns the refusal an error carries; zero when it has none.
func RefusalOf(err error) Refusal {
	var re *refusalError
	if errors.As(err, &re) {
		return re.r
	}
	return Refusal{}
}

// WithRefusal wraps err with r, for the caller to read back with
// RefusalOf.
func WithRefusal(err error, r Refusal) error { return &refusalError{err: err, r: r} }

type account struct {
	Failures      []time.Time `json:"failures,omitempty"`
	LockedUntil   *time.Time  `json:"lockedUntil,omitempty"`
	UntilUnlocked bool        `json:"untilUnlocked,omitempty"`
	LastStep      uint64      `json:"lastStep,omitempty"`
}

type source struct {
	Failures []time.Time `json:"failures,omitempty"`
	Until    *time.Time  `json:"until,omitempty"`
}

type file struct {
	Accounts map[string]*account `json:"accounts"`
	Sources  map[string]*source  `json:"sources"`
}

// Book is the lockout state.
type Book struct {
	path string
	mu   sync.Mutex
	f    file
}

// Open reads the book at path; a missing file is an empty book.
func Open(path string) (*Book, error) {
	b := &Book{path: path, f: file{Accounts: map[string]*account{}, Sources: map[string]*source{}}}
	data, err := os.ReadFile(path) // #nosec G304 -- the lockout file on the state volume
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return b, nil
	case err != nil:
		return nil, fmt.Errorf("lockout: %w", err)
	}
	if err := json.Unmarshal(data, &b.f); err != nil {
		return nil, fmt.Errorf("lockout: %s doesn't parse: %w", path, err)
	}
	if b.f.Accounts == nil {
		b.f.Accounts = map[string]*account{}
	}
	if b.f.Sources == nil {
		b.f.Sources = map[string]*source{}
	}
	return b, nil
}

// Check refuses a try from source for admin (empty when the name is
// unknown) while the source is throttled or the account locked.
func (b *Book) Check(admin, src string, now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s := b.f.Sources[src]; s != nil && s.Until != nil && now.Before(*s.Until) {
		return WithRefusal(codes.New(codes.AccessThrottled, "too many failed tries from %s; try again after %s", src, s.Until.UTC().Format(time.RFC3339)), Refusal{RetryAfter: *s.Until})
	}
	if admin == "" {
		return nil
	}
	a := b.f.Accounts[admin]
	if a == nil {
		return nil
	}
	if a.UntilUnlocked {
		return WithRefusal(codes.New(codes.AccessLocked, "%s is locked after %d failed tries; an owner must unlock it", admin, MaxFailures), Refusal{UntilUnlocked: true})
	}
	if a.LockedUntil != nil && now.Before(*a.LockedUntil) {
		return WithRefusal(codes.New(codes.AccessLocked, "%s is locked after %d failed tries until %s", admin, MaxFailures, a.LockedUntil.UTC().Format(time.RFC3339)), Refusal{LockedUntil: *a.LockedUntil})
	}
	return nil
}

// Fail records a failed try and returns what it leaves: the tries left, or
// the lock it caused.
func (b *Book) Fail(admin, src string, now time.Time, mode Mode) Refusal {
	b.mu.Lock()
	defer b.mu.Unlock()
	var r Refusal
	if src != "" {
		s := b.f.Sources[src]
		if s == nil {
			s = &source{}
			b.f.Sources[src] = s
		}
		s.Failures = append(within(s.Failures, now, SourceWindow), now)
		if len(s.Failures) >= SourceMax {
			until := now.Add(SourceHold)
			s.Until, s.Failures = &until, nil
			r.RetryAfter = until
		}
	}
	if admin != "" {
		a := b.f.Accounts[admin]
		if a == nil {
			a = &account{}
			b.f.Accounts[admin] = a
		}
		a.Failures = append(within(a.Failures, now, Window), now)
		r.AttemptsLeft = max(MaxFailures-len(a.Failures), 0)
		if len(a.Failures) >= MaxFailures {
			a.Failures = nil
			if mode == UntilUnlocked {
				a.UntilUnlocked, r.UntilUnlocked = true, true
			} else {
				until := now.Add(LockFor)
				a.LockedUntil, r.LockedUntil = &until, until
			}
		}
	}
	b.save()
	return r
}

// Succeed resets admin's count after a good try.
func (b *Book) Succeed(admin string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if a := b.f.Accounts[admin]; a != nil && (len(a.Failures) > 0 || a.LockedUntil != nil) {
		a.Failures, a.LockedUntil = nil, nil
		b.save()
	}
}

// Unlock ends admin's lock; it reports whether there was one.
func (b *Book) Unlock(admin string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	a := b.f.Accounts[admin]
	if a == nil || (!a.UntilUnlocked && a.LockedUntil == nil && len(a.Failures) == 0) {
		return false
	}
	a.UntilUnlocked, a.LockedUntil, a.Failures = false, nil, nil
	b.save()
	return true
}

// LastStep is the last TOTP step admin used.
func (b *Book) LastStep(admin string) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if a := b.f.Accounts[admin]; a != nil {
		return a.LastStep
	}
	return 0
}

// SetStep records the TOTP step admin just used.
func (b *Book) SetStep(admin string, step uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	a := b.f.Accounts[admin]
	if a == nil {
		a = &account{}
		b.f.Accounts[admin] = a
	}
	a.LastStep = max(a.LastStep, step)
	b.save()
}

// Forget drops admin from the book (the admin was removed, or got new
// credentials).
func (b *Book) Forget(admin string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.f.Accounts[admin]; ok {
		delete(b.f.Accounts, admin)
		b.save()
	}
}

// AccountState is an admin's lockout, for the Access page.
type AccountState struct {
	Failures      int
	LockedUntil   time.Time
	UntilUnlocked bool
}

// State is admin's lockout at now.
func (b *Book) State(admin string, now time.Time) AccountState {
	b.mu.Lock()
	defer b.mu.Unlock()
	a := b.f.Accounts[admin]
	if a == nil {
		return AccountState{}
	}
	st := AccountState{Failures: len(within(a.Failures, now, Window)), UntilUnlocked: a.UntilUnlocked}
	if a.LockedUntil != nil && now.Before(*a.LockedUntil) {
		st.LockedUntil = *a.LockedUntil
		st.Failures = MaxFailures
	}
	return st
}

func within(ts []time.Time, now time.Time, w time.Duration) []time.Time {
	return slices.DeleteFunc(slices.Clone(ts), func(t time.Time) bool { return !now.Before(t.Add(w)) })
}

// save writes the book; a write that fails leaves the in-memory book, which
// still applies until the next restart. Caller holds mu.
func (b *Book) save() {
	data, err := json.Marshal(b.f)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(b.path), 0o700); err != nil {
		return
	}
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, b.path)
}
