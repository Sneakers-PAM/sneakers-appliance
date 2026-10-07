// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package setup is the first-boot step machine: the steps in their order,
// and the progress file that lets a box resume after a power cut. Before
// the protection step the state volume may not exist yet, so the progress
// is kept on the tmpfs; the protection step moves it to the state volume.
package setup

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

// Step is one first-boot step.
type Step string

// The steps, in order (spec 2 Section 2.1).
const (
	StepNetwork    Step = "network"
	StepProtection Step = "protection"
	StepAdmin      Step = "admin"
	StepRecovery   Step = "recovery"
	StepSignIn     Step = "signin"
	StepDone       Step = "done"
)

// Order is every step in order.
var Order = []Step{StepNetwork, StepProtection, StepAdmin, StepRecovery, StepSignIn, StepDone}

// ProgressFile is the progress file's name in both directories.
const ProgressFile = "progress.json"

// The box's directories.
const (
	TmpDir   = "/run/sneakers/setup"
	StateDir = "/var/lib/sneakers/setup"
)

// Paths are the tmpfs and the state volume's setup directories.
type Paths struct{ Tmp, State string }

// BoxPaths are the box's.
var BoxPaths = Paths{Tmp: TmpDir, State: StateDir}

// Progress is the steps done so far.
type Progress struct {
	Steps   []Step    `json:"done"`
	Updated time.Time `json:"updated"`
}

// Done reports whether s is done.
func (p Progress) Done(s Step) bool { return slices.Contains(p.Steps, s) }

// Machine runs the steps in order.
type Machine struct {
	p  Paths
	mu sync.Mutex
	pr Progress
}

// Open reads the progress: the state volume's when it has one, else the
// tmpfs's. A progress file that doesn't parse is an error, so a box that
// may be set up never runs its steps again by accident.
func Open(p Paths) (*Machine, error) {
	m := &Machine{p: p}
	pr, err := read(p)
	if err != nil {
		return nil, err
	}
	m.pr = pr
	return m, nil
}

// ReadProgress is the progress as accessd reads it for its invariants; an
// unreadable file reads as nothing done.
func ReadProgress(p Paths) Progress {
	pr, _ := read(p)
	return pr
}

func read(p Paths) (Progress, error) {
	for _, dir := range []string{p.State, p.Tmp} {
		b, err := os.ReadFile(filepath.Join(dir, ProgressFile)) // #nosec G304 -- the setup directories
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return Progress{}, err
		}
		var pr Progress
		if err := json.Unmarshal(b, &pr); err != nil {
			return Progress{}, fmt.Errorf("setup: %s: %w", filepath.Join(dir, ProgressFile), err)
		}
		return pr, nil
	}
	return Progress{}, nil
}

// Next is the first step not done; empty once every step is.
func (m *Machine) Next() Step {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.next()
}

func (m *Machine) next() Step {
	for _, s := range Order {
		if !m.pr.Done(s) {
			return s
		}
	}
	return ""
}

// Done reports whether s is done.
func (m *Machine) Done(s Step) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pr.Done(s)
}

// Complete marks s done. Only the next step can be: anything else is
// SETUP_INCOMPLETE naming the step that's open.
func (m *Machine) Complete(s Step) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n := m.next(); s != n {
		if n == "" {
			return codes.New(codes.SetupIncomplete, "setup is already done")
		}
		return codes.New(codes.SetupIncomplete, "the %s step is still open, so %s can't be done yet", n, s)
	}
	pr := Progress{Steps: append(append([]Step(nil), m.pr.Steps...), s), Updated: time.Now().UTC()}
	dir := m.p.Tmp
	if pr.Done(StepProtection) {
		dir = m.p.State
	}
	if err := write(dir, pr); err != nil {
		return err
	}
	if s == StepProtection {
		// The state volume has the progress now; the tmpfs copy would only
		// go stale.
		if err := os.Remove(filepath.Join(m.p.Tmp, ProgressFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	m.pr = pr
	return nil
}

func write(dir string, pr Progress) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	b, err := json.Marshal(pr)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ProgressFile+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the setup directory
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("setup: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("setup: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	return os.Rename(tmp, filepath.Join(dir, ProgressFile))
}
