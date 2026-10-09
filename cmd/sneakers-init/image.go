// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	log "github.com/Bugs5382/go-log"
	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/partition/gpt"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bootcmd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/imageupgrade"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/switchroot"
)

// imageWorkDir holds a fetched release while it's staged; it's on the
// state volume because a root image doesn't fit in /run.
const imageWorkDir = stateDir + "/image-stage"

// newImages builds the stager ImageService runs on: the mounted ESP, the
// boot disk's root slots and the unlocked custody for the sealed copies.
func newImages(pins release.Pins, kc *keycustody.Custody, lg log.Logger) (*imageupgrade.Stager, error) {
	b, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return nil, err
	}
	p, err := bootcmd.Parse(string(b))
	if err != nil {
		return nil, err
	}
	running, err := bootcmd.SlotGUID(p.RootHash)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(imageWorkDir, 0o700); err != nil {
		return nil, err
	}
	return &imageupgrade.Stager{
		ESP:     dirESP{root: espMount},
		Slots:   &gptSlots{disk: bootDisk(), running: running, list: switchroot.NewSystem().Partitions, log: lg},
		Sealer:  kc,
		Pins:    pins,
		Running: p.Version,
		WorkDir: imageWorkDir,
		Logger:  lg,
	}, nil
}

// dirESP is the ESP mounted at root. Writes go to a temporary file that is
// synced, renamed into place and the directory synced, so a cut-off write
// never leaves a half entry.
type dirESP struct{ root string }

func (e dirESP) List(rel string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(e.root, rel))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ents))
	for _, x := range ents {
		out = append(out, x.Name())
	}
	sort.Strings(out)
	return out, nil
}

func (e dirESP) WriteFile(rel string, r io.Reader) error {
	p := filepath.Join(e.root, rel)
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- a path under the ESP mount
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	return syncDir(dir)
}

func (e dirESP) Rename(from, to string) error {
	if err := os.Rename(filepath.Join(e.root, from), filepath.Join(e.root, to)); err != nil {
		return err
	}
	return syncDir(filepath.Dir(filepath.Join(e.root, to)))
}

func (e dirESP) Remove(rel string) error {
	if err := os.Remove(filepath.Join(e.root, rel)); err != nil {
		return err
	}
	return syncDir(filepath.Dir(filepath.Join(e.root, rel)))
}

func (e dirESP) Open(rel string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(e.root, rel)) // #nosec G304 -- a path under the ESP mount
}

func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- a directory under the ESP mount
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// gptSlots writes the root slot the box isn't running from (the root slot
// whose PARTUUID isn't running) and then sets its PARTUUID in the GPT.
type gptSlots struct {
	disk    string
	running string
	list    func() ([]switchroot.Partition, error)
	log     log.Logger
}

func (s *gptSlots) inactive() (switchroot.Partition, error) {
	parts, err := s.list()
	if err != nil {
		return switchroot.Partition{}, err
	}
	var slots []switchroot.Partition
	booted := false
	for _, p := range parts {
		if p.Label != switchroot.LabelRootA && p.Label != switchroot.LabelRootB {
			continue
		}
		if strings.EqualFold(p.PartUUID, s.running) {
			booted = true
			continue
		}
		slots = append(slots, p)
	}
	if !booted || len(slots) != 1 {
		return switchroot.Partition{}, fmt.Errorf("init: expected the running root slot and one other; found running=%v others=%d", booted, len(slots))
	}
	return slots[0], nil
}

// OpenActive opens the root slot the box runs from, read only: a patch's
// base.
func (s *gptSlots) OpenActive(context.Context) (io.ReaderAt, io.Closer, error) {
	parts, err := s.list()
	if err != nil {
		return nil, nil, err
	}
	for _, p := range parts {
		if (p.Label == switchroot.LabelRootA || p.Label == switchroot.LabelRootB) && strings.EqualFold(p.PartUUID, s.running) {
			f, err := os.Open(p.Device) // #nosec G304 -- the running root slot found by its GPT label and PARTUUID
			if err != nil {
				return nil, nil, err
			}
			s.log.Info("init: reading the running root slot for a patch", log.F("slot", p.Label), log.F("device", p.Device))
			return f, f, nil
		}
	}
	return nil, nil, fmt.Errorf("init: the running root slot (PARTUUID %s) wasn't found", s.running)
}

func (s *gptSlots) WriteInactive(_ context.Context, r io.Reader, size int64, partUUID string) error {
	if s.disk == "" {
		return errors.New("init: the boot disk wasn't found")
	}
	slot, err := s.inactive()
	if err != nil {
		return err
	}
	s.log.Info("init: writing the inactive root slot", log.F("slot", slot.Label), log.F("device", slot.Device), log.F("bytes", size))
	f, err := os.OpenFile(slot.Device, os.O_WRONLY, 0) // #nosec G304 -- a root slot found by its GPT label
	if err != nil {
		return err
	}
	n, err := io.Copy(f, r)
	if err == nil && n != size {
		err = fmt.Errorf("init: wrote %d of %d root image bytes", n, size)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return s.setPartUUID(slot.Label, partUUID)
}

// setPartUUID rewrites both GPT copies with the slot's new GUID, straight
// through the table: Disk.Partition would ask the kernel to re-read the
// whole table, which it refuses while the ESP is mounted. The new GUID is
// read at the next boot.
func (s *gptSlots) setPartUUID(label, guid string) error {
	d, err := diskfs.Open(s.disk, diskfs.WithOpenMode(diskfs.ReadWrite))
	if err != nil {
		return fmt.Errorf("init: open %s: %w", s.disk, err)
	}
	defer func() { _ = d.Close() }()
	t, err := d.GetPartitionTable()
	if err != nil {
		return fmt.Errorf("init: read the partition table: %w", err)
	}
	gt, ok := t.(*gpt.Table)
	if !ok {
		return fmt.Errorf("init: %s has no GPT", s.disk)
	}
	found := false
	for _, p := range gt.Partitions {
		if p.Type != gpt.Unused && p.Name == label {
			p.GUID, found = strings.ToUpper(guid), true
		}
	}
	if !found {
		return fmt.Errorf("init: no %s partition in the GPT", label)
	}
	w, err := d.Backend.Writable()
	if err != nil {
		return err
	}
	if err := gt.Write(w, d.Size); err != nil {
		return fmt.Errorf("init: write the partition table: %w", err)
	}
	s.log.Info("init: root slot PARTUUID set", log.F("slot", label), log.F("partuuid", guid))
	return nil
}
