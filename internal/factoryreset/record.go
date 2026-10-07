// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package factoryreset

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// RecordName is the record's file on the ESP.
const RecordName = "reset.json"

// Step is how far a reset has got. Each is written to the record once it
// is complete, so a resume starts at the first step not recorded.
type Step string

// The steps, in order.
const (
	// StepBegun: the record is written and nothing is destroyed yet.
	StepBegun Step = "begun"
	// StepStopped: the services are drained and the volumes closed.
	StepStopped Step = "stopped"
	// StepWiped: the LUKS2 headers and key slots (with the TPM-sealed
	// tokens in them) and the key file are overwritten.
	StepWiped Step = "wiped"
	// StepDeleted: the partitions are gone from both GPT copies.
	StepDeleted Step = "deleted"
	// StepDone: the check passed. The record stays as the one trace of the
	// reset that survives it.
	StepDone Step = "done"
)

// Region is one partition the reset destroys, recorded before anything is
// touched so a resume still knows where it was once it's out of the GPT.
type Region struct {
	Number int    `json:"number"`
	Label  string `json:"label"`
	Start  int64  `json:"start"`
	Size   int64  `json:"size"`
}

// Record is reset.json.
type Record struct {
	ID        string    `json:"id"`
	StartedBy string    `json:"startedBy"`
	Approvals []string  `json:"approvals"`
	Requested time.Time `json:"requested"`
	Step      Step      `json:"step"`
	Regions   []Region  `json:"regions"`
	// Attempts counts the runs, the first and every resume after a cut.
	Attempts  int       `json:"attempts"`
	LastError string    `json:"lastError,omitempty"`
	Finished  time.Time `json:"finished,omitzero"`
}

// Pending reports whether the reset is unfinished: init then runs the rest
// of it and never boots normally.
func (r Record) Pending() bool { return r.Step != StepDone }

// RecordStore keeps the record.
type RecordStore interface {
	// Read returns the record, and false when there is none.
	Read() (Record, bool, error)
	// Write replaces the record durably.
	Write(Record) error
}

// FileStore keeps the record in Dir, the mounted ESP.
type FileStore struct{ Dir string }

// Read returns the record. The new copy is read when the old name is gone
// or doesn't parse: on FAT a cut during the rename can leave either.
func (s FileStore) Read() (Record, bool, error) {
	var firstErr error
	for _, name := range []string{RecordName, RecordName + ".new"} {
		b, err := os.ReadFile(filepath.Join(s.Dir, name)) // #nosec G304 -- the record on the ESP
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err == nil {
			var r Record
			if err = json.Unmarshal(b, &r); err == nil {
				return r, true, nil
			}
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("factory reset: %s: %w", name, err)
		}
	}
	if firstErr != nil {
		// A record that's there but unreadable still means a reset was
		// started: the caller treats it as pending.
		return Record{Step: StepBegun}, true, firstErr
	}
	return Record{}, false, nil
}

// Write writes the record to a new file, syncs it, renames it over the old
// one and syncs the directory.
func (s FileStore) Write(r Record) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.Dir, RecordName+".new")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the record on the ESP
	if err != nil {
		return fmt.Errorf("factory reset: write the record: %w", err)
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("factory reset: write the record: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("factory reset: sync the record: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.Dir, RecordName)); err != nil {
		return fmt.Errorf("factory reset: rename the record: %w", err)
	}
	d, err := os.Open(s.Dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
