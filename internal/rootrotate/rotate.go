// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package rootrotate moves the vault's root key on the box to a new key
// without a moment in which a key that something still needs is gone.
//
// The live key is in the box's secrets store; the sealed item is a copy of
// it. The rotation makes the new key and keeps the old one as the previous
// key, seals the new one as a staging item and refreshes the escrow so it
// carries both, then applies and restarts the vault, which re-wraps its
// working keys under the new one and reads each back. Only when the vault
// says verified, from a pod started after the restart, is the previous key
// dropped; the vault is applied and restarted once more on the new key
// alone, and only then is the canonical sealed item replaced from it, the
// staging copy retired by name and a final escrow written that carries only
// the new set. Every step can run again: the state file says where to carry
// on, and the store's own previous key says whether the new key was already
// made. A failure stops with both keys kept (docs/key-custody.md).
package rootrotate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// The states the vault reports at its health check.
const (
	StateNone       = "none"
	StateInProgress = "in-progress"
	StateVerified   = "verified"
	StateFailed     = "failed"
)

// VaultStatus is what the vault says about the move: a state and the number
// of working keys not yet on the current root key. Never a key.
type VaultStatus struct {
	State   string
	Pending int
}

// Keys are the two values of a rotation; both are secrets, never logged.
type Keys struct {
	Current  string
	Previous string
}

// ErrNotVerified is returned when the vault didn't report verified in time,
// or reported failed. Nothing was dropped, replaced or retired.
var ErrNotVerified = errors.New("rootrotate: the vault didn't verify the move to the new root key; both keys are kept")

// Env is the box the rotation works on.
type Env interface {
	// Begin makes the new key and keeps the old as the previous key in one
	// write, or returns the keys of a rotation already begun.
	Begin(ctx context.Context) (Keys, error)
	// SealStaging seals the new key as the staging item.
	SealStaging(ctx context.Context, key []byte) error
	// RefreshEscrow seals what the product's keys need and writes a new
	// escrow to the recovery keys.
	RefreshEscrow(ctx context.Context) error
	// Apply writes the box secrets stack and waits until k0s has applied it.
	Apply(ctx context.Context) error
	// Restart restarts the vault, waits until it has rolled out, and
	// returns the time it was restarted.
	Restart(ctx context.Context) (time.Time, error)
	// Status is the vault's report, from a pod that started at or after
	// notBefore; it is an error until there is one.
	Status(ctx context.Context, notBefore time.Time) (VaultStatus, error)
	// End drops the previous key.
	End(ctx context.Context) error
	// CurrentKey is the new key, as the store holds it.
	CurrentKey(ctx context.Context) ([]byte, error)
	// SealCanonical replaces the canonical sealed item with key.
	SealCanonical(ctx context.Context, key []byte) error
	// RetireStaging deletes the staging item by name.
	RetireStaging(ctx context.Context) error
	// Audit records an event. names are item names, never values.
	Audit(event string, names ...string)
}

// Runner runs a rotation.
type Runner struct {
	Env Env
	// StateFile is where the rotation keeps the step it has reached.
	StateFile string
	// Poll and Bound are how often the vault is asked and how long a wait
	// lasts.
	Poll, Bound time.Duration
	// Key and Staging are the names of the key and its staging item, for
	// the audit.
	Key, Staging string
}

const (
	stepBegin  = "begin"
	stepApply  = "apply"
	stepVerify = "verify"
	stepDrop   = "drop"
	stepSettle = "settle"
	stepSeal   = "seal"
	stepRetire = "retire"
	stepEscrow = "escrow"
)

type state struct {
	Step        string    `json:"step"`
	RestartedAt time.Time `json:"restarted_at,omitzero"`
	// Failed says why the last run stopped, in words that carry no key.
	Failed string `json:"failed,omitempty"`
}

func (r *Runner) load() (state, error) {
	b, err := os.ReadFile(r.StateFile) // #nosec G304 -- the box's own rotation state file
	if errors.Is(err, fs.ErrNotExist) {
		return state{Step: stepBegin}, nil
	}
	if err != nil {
		return state{}, fmt.Errorf("rootrotate: %w", err)
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return state{}, fmt.Errorf("rootrotate: %s doesn't parse: %w", filepath.Base(r.StateFile), err)
	}
	return st, nil
}

func (r *Runner) save(st state) error {
	b, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("rootrotate: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(r.StateFile), 0o700); err != nil {
		return fmt.Errorf("rootrotate: %w", err)
	}
	tmp := r.StateFile + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the box's own rotation state file
	if err != nil {
		return fmt.Errorf("rootrotate: %w", err)
	}
	if _, err := f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rootrotate: %w", err)
	}
	if err := os.Rename(tmp, r.StateFile); err != nil {
		return fmt.Errorf("rootrotate: %w", err)
	}
	return nil
}

// Active reports whether a rotation has begun and not finished.
func (r *Runner) Active() bool {
	_, err := os.Stat(r.StateFile)
	return err == nil
}

// Run carries the rotation on from the step the state file names, to its
// end or the first step that stops it.
func (r *Runner) Run(ctx context.Context) error {
	st, err := r.load()
	if err != nil {
		return err
	}
	to := func(step string, at time.Time) error {
		st = state{Step: step, RestartedAt: at}
		return r.save(st)
	}
	for {
		switch st.Step {
		case stepBegin:
			keys, err := r.Env.Begin(ctx)
			if err != nil {
				return err
			}
			if err := r.Env.SealStaging(ctx, []byte(keys.Current)); err != nil {
				return err
			}
			// The escrow carries both keys through the window: the canonical item
			// still holds the old one, the staging item the new.
			if err := r.Env.RefreshEscrow(ctx); err != nil {
				return err
			}
			r.Env.Audit("root key rotation begun; an escrow was issued", r.Key, r.Staging)
			if err := to(stepApply, time.Time{}); err != nil {
				return err
			}
		case stepApply:
			at, err := r.applyAndRestart(ctx)
			if err != nil {
				return err
			}
			if err := to(stepVerify, at); err != nil {
				return err
			}
		case stepVerify:
			if st.Failed != "" {
				// The vault tries the move again at its next start.
				if err := to(stepApply, time.Time{}); err != nil {
					return err
				}
				continue
			}
			if err := r.wait(ctx, st.RestartedAt, StateVerified); err != nil {
				st.Failed = err.Error()
				if serr := r.save(st); serr != nil {
					return serr
				}
				r.Env.Audit("root key rotation stopped; both keys are kept", r.Key)
				return err
			}
			if err := to(stepDrop, time.Time{}); err != nil {
				return err
			}
		case stepDrop:
			if err := r.Env.End(ctx); err != nil {
				return err
			}
			r.Env.Audit("root key rotation: the previous key is dropped", r.Key)
			at, err := r.applyAndRestart(ctx)
			if err != nil {
				return err
			}
			if err := to(stepSettle, at); err != nil {
				return err
			}
		case stepSettle:
			if st.RestartedAt.IsZero() {
				// Died between the drop and the restart's record: apply again.
				if err := to(stepDrop, time.Time{}); err != nil {
					return err
				}
				continue
			}
			if err := r.wait(ctx, st.RestartedAt, StateNone); err != nil {
				return err
			}
			if err := to(stepSeal, time.Time{}); err != nil {
				return err
			}
		case stepSeal:
			key, err := r.Env.CurrentKey(ctx)
			if err != nil {
				return err
			}
			if err := r.Env.SealCanonical(ctx, key); err != nil {
				return err
			}
			if err := to(stepRetire, time.Time{}); err != nil {
				return err
			}
		case stepRetire:
			if err := r.Env.RetireStaging(ctx); err != nil {
				return err
			}
			r.Env.Audit("root key rotation: the staging item is retired", r.Staging)
			if err := to(stepEscrow, time.Time{}); err != nil {
				return err
			}
		case stepEscrow:
			if err := r.Env.RefreshEscrow(ctx); err != nil {
				return err
			}
			r.Env.Audit("root key rotation finished; an escrow with only the new key was issued", r.Key)
			if err := os.Remove(r.StateFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("rootrotate: %w", err)
			}
			return nil
		default:
			return fmt.Errorf("rootrotate: %s names the unknown step %q", filepath.Base(r.StateFile), st.Step)
		}
	}
}

func (r *Runner) applyAndRestart(ctx context.Context) (time.Time, error) {
	if err := r.Env.Apply(ctx); err != nil {
		return time.Time{}, err
	}
	return r.Env.Restart(ctx)
}

// wait asks the vault, from a pod started at or after notBefore, until it
// reports want. Failed stops at once; an error, or any other state, is a
// vault that isn't there yet, and the wait goes on up to Bound.
func (r *Runner) wait(ctx context.Context, notBefore time.Time, want string) error {
	ctx, cancel := context.WithTimeout(ctx, r.Bound)
	defer cancel()
	last := "no answer"
	for {
		s, err := r.Env.Status(ctx, notBefore)
		switch {
		case err != nil:
			last = "no answer from a vault started after the restart"
		case s.State == want:
			return nil
		case s.State == StateFailed:
			return fmt.Errorf("%w: the vault reports failed with %d working keys not moved", ErrNotVerified, s.Pending)
		default:
			last = fmt.Sprintf("the vault reports %s (%d not moved)", s.State, s.Pending)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %s", ErrNotVerified, last)
		case <-time.After(r.Poll):
		}
	}
}

// Progress is where a rotation that hasn't finished stands: the step it
// will carry on from, and why it stopped, if it did. active is false when no
// rotation is begun.
func (r *Runner) Progress() (step, why string, active bool, err error) {
	st, err := r.load()
	if err != nil {
		return "", "", false, err
	}
	if !r.Active() {
		return "", "", false, nil
	}
	return st.Step, st.Failed, true, nil
}
