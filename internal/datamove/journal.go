// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package datamove

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// JournalFile is the journal's name in the platform settings directory.
const JournalFile = "data-move.json"

// State is where a move stands.
type State string

// The states of a move. No journal is a move that never started.
const (
	// StateRunning is on disk only while a move runs; found at the start
	// of a run, it means the move was cut off.
	StateRunning State = "running"
	// StateFailed left the old cluster as it was; the next apply tries
	// again from the start.
	StateFailed State = "failed"
	// StateSwitched verified the target; the services run on it, and the
	// box hasn't proven healthy yet.
	StateSwitched State = "switched"
	// StateDone is healthy on the target, for good.
	StateDone State = "done"
)

// Step is a part of a move.
type Step string

// The steps, in order.
const (
	StepPrepare Step = "prepare"
	StepStop    Step = "stop"
	StepDump    Step = "dump"
	StepTarget  Step = "target"
	StepRestore Step = "restore"
	StepCheck   Step = "check"
	StepStart   Step = "start"
)

// ErrInterrupted is a move an earlier run started and never ended.
var ErrInterrupted = errors.New("the move was cut off")

// Journal records how far a move got. It holds no value of the data.
type Journal struct {
	State   State `json:"state"`
	Step    Step  `json:"step"`
	Attempt int   `json:"attempt"`
	// TargetTouched: an attempt wrote to the target, so a later one may
	// clear it. It's what stops a move dropping data it didn't write.
	TargetTouched bool `json:"target_touched"`
	// Nothing: the source held no tables, so nothing moved.
	Nothing  bool      `json:"nothing,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
}

// Read returns the journal; an empty one when no move started.
func (m *Move) Read() (*Journal, error) {
	b, err := os.ReadFile(m.Journal)
	if errors.Is(err, fs.ErrNotExist) {
		return &Journal{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("datamove: read the journal: %w", err)
	}
	j := &Journal{}
	if err := json.Unmarshal(b, j); err != nil {
		return nil, fmt.Errorf("datamove: read the journal: %w", err)
	}
	return j, nil
}

// save writes the journal and has it on disk before it returns, so a power
// loss can't lose a state the box acted on.
func (m *Move) save(j *Journal) error {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return fmt.Errorf("datamove: write the journal: %w", err)
	}
	dir := filepath.Dir(m.Journal)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("datamove: write the journal: %w", err)
	}
	tmp := m.Journal + ".new"
	if err := writeSynced(tmp, b); err != nil {
		return fmt.Errorf("datamove: write the journal: %w", err)
	}
	if err := os.Rename(tmp, m.Journal); err != nil {
		return fmt.Errorf("datamove: write the journal: %w", err)
	}
	return syncDir(dir)
}

func writeSynced(p string, b []byte) (err error) {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- the move's own files
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	if _, err := f.Write(b); err != nil {
		return err
	}
	return f.Sync()
}

func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the move's own directory
	if err != nil {
		return fmt.Errorf("datamove: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("datamove: %w", err)
	}
	return nil
}
