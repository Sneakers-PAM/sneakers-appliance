// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package factoryreset carries out the factory reset (spec 5, Section
// 2.8.1) once init has checked its quorum: it destroys the state, backup
// and key-file partitions and every key that opens them, removes them from
// the GPT and checks they're gone, so the next boot is a genuine first
// boot. Every step is recorded in reset.json on the ESP before the next
// starts; a power cut resumes at the first unrecorded step, and while the
// record is pending init never boots normally.
//
// The partitions are deleted, not just their key slots: first boot plans
// into the free space after the installed partitions, so a box whose old
// LUKS header is gone but whose partition is still there could neither
// open nor re-create its volume (the reset loop a sister project hit).
package factoryreset

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
)

// Labels are the partitions a reset destroys. The ESP and both root slots
// (the installed release) stay.
var Labels = []string{disk.LabelKeyfile, disk.LabelState, disk.LabelBackup}

// The areas overwritten in each partition.
const (
	// HeaderArea holds the LUKS2 headers (both copies), their JSON areas
	// with the TPM-sealed tokens, and the key slots: overwritten with random
	// data. The key file partition is no bigger, so all of it goes.
	HeaderArea = 16 * disk.MiB
	// ZeroArea is then zeroed, as wipefs would, so no LUKS, filesystem or
	// GPT signature can appear by chance in the random bytes.
	ZeroArea = 4 * disk.MiB
	// TailArea at the end is overwritten too (signatures some tools keep
	// there).
	TailArea = disk.MiB
)

var (
	luksMagic  = []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}
	luksMagic2 = []byte{'S', 'K', 'U', 'L', 0xba, 0xbe}
)

// Disk is the boot disk as the reset uses it.
type Disk interface {
	Partitions() ([]Region, error)
	BackupLabels() ([]string, error)
	WriteAt(b []byte, off int64) (int, error)
	ReadAt(b []byte, off int64) (int, error)
	Delete(numbers []int) error
}

// Deps are the reset's collaborators.
type Deps struct {
	Store RecordStore
	Disk  Disk
	// Stop drains the services and unmounts and closes the volumes. Nil
	// on a resume at boot, when nothing was started.
	Stop func(ctx context.Context) error
	// Rand is the overwrite source; nil means crypto/rand.
	Rand io.Reader
	Now  func() time.Time
	Logf func(format string, args ...any)
}

func (d *Deps) defaults() {
	if d.Rand == nil {
		d.Rand = rand.Reader
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logf == nil {
		d.Logf = func(string, ...any) {}
	}
}

// Begin records the reset and the partitions it will destroy before
// anything is touched. Once it returns, the box can only finish the reset.
func Begin(d Deps, r Record) (Record, error) {
	d.defaults()
	parts, err := d.Disk.Partitions()
	if err != nil {
		return Record{}, codes.Wrap(codes.ResetFailed, err)
	}
	r.Regions = nil
	for _, p := range parts {
		if slices.Contains(Labels, p.Label) {
			r.Regions = append(r.Regions, p)
		}
	}
	r.Step, r.Requested, r.Attempts, r.LastError, r.Finished = StepBegun, d.Now().UTC(), 0, "", time.Time{}
	if err := d.Store.Write(r); err != nil {
		return Record{}, codes.Wrap(codes.ResetFailed, err)
	}
	d.Logf("factory reset %s: begun by %s; destroying %d partitions", r.ID, r.StartedBy, len(r.Regions))
	return r, nil
}

// Run carries the recorded reset on from its last completed step to done.
// A failure is recorded and returned; the reset stays pending.
func Run(ctx context.Context, d Deps) (Record, error) {
	d.defaults()
	r, ok, err := d.Store.Read()
	if err != nil {
		return r, codes.Wrap(codes.ResetFailed, err)
	}
	if !ok {
		return r, codes.New(codes.ResetFailed, "there is no factory reset to run")
	}
	if !r.Pending() {
		return r, nil
	}
	r.Attempts++
	if r.Attempts > 1 {
		d.Logf("factory reset %s: resuming after %s (attempt %d)", r.ID, r.Step, r.Attempts)
	}
	if err := d.Store.Write(r); err != nil {
		return r, codes.Wrap(codes.ResetFailed, err)
	}
	steps := []struct {
		after Step
		name  string
		run   func() error
	}{
		{StepBegun, "stop the services and close the volumes", func() error {
			if d.Stop == nil {
				return nil
			}
			return d.Stop(ctx)
		}},
		{StepStopped, "overwrite the headers, key slots and key file", func() error { return wipe(d, r.Regions) }},
		{StepWiped, "delete the partitions", func() error { return remove(d, r.Regions) }},
		{StepDeleted, "check the partitions and signatures are gone", func() error { return check(d, r.Regions) }},
	}
	for i, s := range steps {
		if order(r.Step) > order(s.after) {
			continue
		}
		next := StepDone
		if i+1 < len(steps) {
			next = steps[i+1].after
		}
		start := d.Now()
		d.Logf("factory reset %s: %s", r.ID, s.name)
		if err := s.run(); err != nil {
			if !codes.Is(err, codes.ResetVerify) {
				err = codes.New(codes.ResetFailed, "%s: %v", s.name, err)
			}
			r.LastError = codes.Describe(err)
			if werr := d.Store.Write(r); werr != nil {
				d.Logf("factory reset %s: the record of the failure wasn't written: %v", r.ID, werr)
			}
			d.Logf("factory reset %s: %s", r.ID, r.LastError)
			return r, err
		}
		r.Step, r.LastError = next, ""
		if next == StepDone {
			r.Finished = d.Now().UTC()
		}
		if err := d.Store.Write(r); err != nil {
			return r, codes.Wrap(codes.ResetFailed, err)
		}
		d.Logf("factory reset %s: %s done in %s", r.ID, s.name, d.Now().Sub(start))
	}
	return r, nil
}

func order(s Step) int {
	return slices.Index([]Step{StepBegun, StepStopped, StepWiped, StepDeleted, StepDone}, s)
}

// wipe overwrites each region's header area and tail with random data,
// then zeroes the start.
func wipe(d Deps, regions []Region) error {
	for _, g := range regions {
		head := min(g.Size, HeaderArea)
		if err := fill(d, g.Start, head, d.Rand); err != nil {
			return fmt.Errorf("%s: %w", g.Label, err)
		}
		if tail := min(TailArea, g.Size-head); tail > 0 {
			if err := fill(d, g.Start+g.Size-tail, tail, d.Rand); err != nil {
				return fmt.Errorf("%s: %w", g.Label, err)
			}
		}
		if err := fill(d, g.Start, min(g.Size, ZeroArea), zeros{}); err != nil {
			return fmt.Errorf("%s: %w", g.Label, err)
		}
	}
	return nil
}

type zeros struct{}

func (zeros) Read(b []byte) (int, error) { clear(b); return len(b), nil }

// fill writes n bytes from src at off in one write (n is at most
// HeaderArea).
func fill(d Deps, off, n int64, src io.Reader) error {
	buf := make([]byte, n)
	if _, err := io.ReadFull(src, buf); err != nil {
		return err
	}
	_, err := d.Disk.WriteAt(buf, off)
	return err
}

// remove deletes the recorded partitions that are still in the table. A
// partition is deleted only when its number, label and start all match
// the record, so a resume can't touch anything else.
func remove(d Deps, regions []Region) error {
	parts, err := d.Disk.Partitions()
	if err != nil {
		return err
	}
	var numbers []int
	for _, p := range parts {
		if slices.ContainsFunc(regions, func(g Region) bool { return g.Number == p.Number && g.Label == p.Label && g.Start == p.Start }) {
			numbers = append(numbers, p.Number)
		}
	}
	if len(numbers) == 0 {
		return nil
	}
	return d.Disk.Delete(numbers)
}

// check re-reads both GPT copies and the regions: none of the partitions
// may be listed, and no region may start with anything but zeros or carry
// a LUKS header magic in its header area.
func check(d Deps, regions []Region) error {
	parts, err := d.Disk.Partitions()
	if err != nil {
		return codes.New(codes.ResetVerify, "re-read the partition table: %v", err)
	}
	for _, p := range parts {
		if slices.Contains(Labels, p.Label) {
			return codes.New(codes.ResetVerify, "partition %d (%s) is still in the GPT", p.Number, p.Label)
		}
	}
	backup, err := d.Disk.BackupLabels()
	if err != nil {
		return codes.New(codes.ResetVerify, "read the backup GPT: %v", err)
	}
	for _, l := range backup {
		if slices.Contains(Labels, l) {
			return codes.New(codes.ResetVerify, "%s is still in the backup GPT", l)
		}
	}
	for _, g := range regions {
		head := make([]byte, min(g.Size, HeaderArea))
		if _, err := d.Disk.ReadAt(head, g.Start); err != nil {
			return codes.New(codes.ResetVerify, "read where %s was: %v", g.Label, err)
		}
		if !bytes.Equal(head[:min(int64(len(head)), ZeroArea)], make([]byte, min(int64(len(head)), ZeroArea))) {
			return codes.New(codes.ResetVerify, "the start of where %s was isn't zeroed", g.Label)
		}
		for off := 0; off+len(luksMagic) <= len(head); off += 4096 {
			if bytes.HasPrefix(head[off:], luksMagic) || bytes.HasPrefix(head[off:], luksMagic2) {
				return codes.New(codes.ResetVerify, "a LUKS header is still at offset %d of where %s was", off, g.Label)
			}
		}
	}
	return nil
}
