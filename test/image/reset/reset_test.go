// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

// Package reset_test is the image suite's factory reset: a box with first
// boot's partitions and a reset that was approved and begun, then cut off
// before it destroyed anything, boots, finishes the reset in init's reset
// phase and reboots, and the next boot is a genuine first boot.
package reset_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/partition/gpt"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/factoryreset"
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

// The fake LUKS2 header magics written at each volume's start, as the
// unit tests do; the reset's check refuses a disk that still has them.
var (
	luksMagic  = []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}
	luksMagic2 = []byte{'S', 'K', 'U', 'L', 0xba, 0xbe}
)

// afterFirstBoot copies the lab image and lays first boot's partitions
// (key-file mode: the key file, state and backup) after the installed ones,
// in both GPT copies, keeping every installed partition's GUID.
func afterFirstBoot(t *testing.T, img string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "box.raw")
	if b, err := exec.Command("cp", "--sparse=always", img, p).CombinedOutput(); err != nil { // #nosec G204 -- fixed tool, the test's files
		t.Fatalf("cp: %v\n%s", err, b)
	}
	d, err := diskfs.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := d.GetPartitionTable()
	if err != nil {
		t.Fatal(err)
	}
	tbl, ok := pt.(*gpt.Table)
	if !ok {
		t.Fatalf("the lab image has no GPT")
	}
	plan, err := disk.FirstBootPlan(d.Size, disk.InstalledBytes("amd64"), "amd64", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range plan {
		tbl.Partitions = append(tbl.Partitions, &gpt.Partition{
			Index: q.Number, Start: uint64(q.Start / disk.SectorSize), End: uint64((q.Start+q.Size)/disk.SectorSize - 1), // #nosec G115 -- the fixed layout
			Size: uint64(q.Size), Type: gpt.Type(q.Type), Name: q.Label, // #nosec G115 -- as above
		})
	}
	if err := d.Partition(tbl); err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	f, err := os.OpenFile(p, os.O_WRONLY, 0) // #nosec G304 -- the test's image
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range plan {
		for off, b := range map[int64][]byte{q.Start: luksMagic, q.Start + 16*1024: luksMagic2} {
			if _, err := f.WriteAt(b, off); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

// begin records an approved reset the way init's Begin does when the
// quorum's delay ends, and puts the record on the image's ESP, so the box
// boots as if the power was cut before the first partition was touched.
func begin(t *testing.T, img string) factoryreset.Record {
	t.Helper()
	esp := t.TempDir()
	rec, err := factoryreset.Begin(factoryreset.Deps{Store: factoryreset.FileStore{Dir: esp}, Disk: &factoryreset.GPTDisk{Path: img}},
		factoryreset.Record{ID: "R-IMAGE1", StartedBy: "alice", Approvals: []string{"alice", "bob"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Regions) != 3 {
		t.Fatalf("the reset records %d partitions, want the key file, state and backup", len(rec.Regions))
	}
	b, err := os.ReadFile(filepath.Join(esp, factoryreset.RecordName)) // #nosec G304 -- the test's record
	if err != nil {
		t.Fatal(err)
	}
	d, err := diskfs.Open(img)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	fsys, err := d.GetFilesystem(1)
	if err != nil {
		t.Fatal(err)
	}
	w, err := fsys.OpenFile("/"+factoryreset.RecordName, os.O_CREATE|os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return rec
}

func espRecord(t *testing.T, img string) factoryreset.Record {
	t.Helper()
	d, err := diskfs.Open(img, diskfs.WithOpenMode(diskfs.ReadOnly))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	fsys, err := d.GetFilesystem(1)
	if err != nil {
		t.Fatal(err)
	}
	f, err := fsys.OpenFile("/"+factoryreset.RecordName, os.O_RDONLY)
	if err != nil {
		t.Fatalf("the ESP has no %s: %v", factoryreset.RecordName, err)
	}
	// go-diskfs reads a FAT file to the end of its last cluster; the
	// record is the first JSON value in it.
	var r factoryreset.Record
	if err := json.NewDecoder(f).Decode(&r); err != nil {
		t.Fatalf("%s: %v", factoryreset.RecordName, err)
	}
	return r
}

func labels(t *testing.T, img string) []string {
	t.Helper()
	parts, err := (&factoryreset.GPTDisk{Path: img}).Partitions()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range parts {
		out = append(out, p.Label)
	}
	return out
}

func TestAResetFinishesAtBootThenFirstBootIsFresh(t *testing.T) {
	img, keys := os.Getenv("SNEAKERS_IMAGE"), os.Getenv("SNEAKERS_KEYS")
	harness.Need(t, nil, img, keys)
	box := afterFirstBoot(t, img)
	rec := begin(t, box)

	vm := harness.Boot(t, harness.Options{SecureBoot: harness.Enrolled, TPM: true, Keys: keys, Disks: []harness.Disk{{Image: box}}})
	vm.Expect(`sneakers-init: phase=reset`, 5*time.Minute)
	vm.Expect(`factory reset is unfinished; finishing it`, time.Minute)
	vm.Expect(`factory reset finished; rebooting into first boot`, 5*time.Minute)
	vm.WaitExit(2 * time.Minute)
	if strings.Contains(vm.Console(), "services: entering phase") {
		t.Fatal("init started services during the reset")
	}

	after := vm.Disk(0)
	got := labels(t, after)
	for _, l := range factoryreset.Labels {
		if slices.Contains(got, l) {
			t.Fatalf("%s is still in the GPT after the reset: %v", l, got)
		}
	}
	for _, l := range []string{disk.LabelESP, disk.LabelRootA, disk.LabelRootB} {
		if !slices.Contains(got, l) {
			t.Fatalf("the reset removed %s: %v", l, got)
		}
	}
	done := espRecord(t, after)
	if done.ID != rec.ID || done.Step != factoryreset.StepDone || done.Finished.IsZero() || done.Attempts != 1 {
		t.Fatalf("the record after the reset: %+v", done)
	}

	// The next boot is first boot, once: no reset phase, no loop back.
	next := harness.Boot(t, harness.Options{SecureBoot: harness.Enrolled, TPM: true, Keys: keys, Disks: []harness.Disk{{Image: after}}})
	next.Expect(`sneakers-init: phase=firstboot`, 5*time.Minute)
	next.Expect(`Use the TPM \(recommended\)`, time.Minute)
	next.Type("\r")
	next.Expect(`services: entering phase phase=firstboot`, 3*time.Minute)
	if c := next.Console(); strings.Contains(c, "phase=reset") || strings.Contains(c, "factory reset is unfinished") {
		t.Fatal("the boot after the reset went back to the reset phase")
	}
}
