// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package keycustody_test

import (
	"path/filepath"
	"slices"
	"testing"

	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/partition/gpt"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/factoryreset"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/power"
)

// installedImage is a sparse disk image with the kit's partitions only, as
// a box is before its first boot.
func installedImage(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vda")
	d, err := diskfs.Create(p, 64*disk.GiB, diskfs.SectorSize512)
	if err != nil {
		t.Fatal(err)
	}
	var parts []*gpt.Partition
	for _, q := range disk.Installed() {
		parts = append(parts, &gpt.Partition{
			Index: q.Number, Start: uint64(q.Start / disk.SectorSize), End: uint64((q.Start+q.Size)/disk.SectorSize - 1), // #nosec G115 -- the fixed layout
			Size: uint64(q.Size), Type: gpt.Type(q.Type), Name: q.Label, // #nosec G115 -- as above
		})
	}
	if err := d.Partition(&gpt.Table{Partitions: parts, LogicalSectorSize: disk.SectorSize, PhysicalSectorSize: disk.SectorSize, ProtectiveMBR: true}); err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	return p
}

func regions(t *testing.T, img string) []factoryreset.Region {
	t.Helper()
	r, err := (&factoryreset.GPTDisk{Path: img}).Partitions()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTheBootDiskAddsFirstBootsPartitionsAfterTheInstalledOnes(t *testing.T) {
	img := installedImage(t)
	before := regions(t, img)
	bd := &keycustody.BootDisk{Path: img}
	if bd.Size() != 64*disk.GiB || bd.Arch() == "" {
		t.Fatalf("size %d arch %q", bd.Size(), bd.Arch())
	}
	plan, err := disk.FirstBootPlan(bd.Size(), disk.InstalledBytes("amd64"), "amd64", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, kf, err := bd.Create(ctx, plan); err != nil || kf == nil {
		t.Fatalf("create: keyfile %v, %v", kf, err)
	}
	got := regions(t, img)
	if !slices.Equal(got[:3], before) {
		t.Fatalf("the installed partitions changed:\n%+v\n%+v", before, got[:3])
	}
	var labels []string
	for i, r := range got[3:] {
		labels = append(labels, r.Label)
		if r.Start != plan[i].Start || r.Size != plan[i].Size || r.Number != plan[i].Number {
			t.Fatalf("partition %d is %+v, planned %+v", i, r, plan[i])
		}
	}
	if !slices.Equal(labels, []string{disk.LabelKeyfile, disk.LabelState, disk.LabelBackup}) {
		t.Fatalf("labels %v", labels)
	}
	state, backup, kf, err := bd.Open(ctx)
	if err != nil || state == nil || backup == nil || kf == nil {
		t.Fatalf("open: %v", err)
	}
	if p := state.(*keycustody.LUKSVolume).Path; p != img+"5" {
		t.Fatalf("state is at %s", p)
	}
}

// First boot cut short after the partitions were made, before the header
// was written, runs again: the partitions are made again for the mode
// chosen this time, never added twice.
func TestARerunFirstBootReplacesItsPartitions(t *testing.T) {
	img := installedImage(t)
	bd := &keycustody.BootDisk{Path: img}
	withKeyfile, _ := disk.FirstBootPlan(bd.Size(), disk.InstalledBytes("amd64"), "amd64", true)
	if _, _, _, err := bd.Create(ctx, withKeyfile); err != nil {
		t.Fatal(err)
	}
	tpmPlan, _ := disk.FirstBootPlan(bd.Size(), disk.InstalledBytes("amd64"), "amd64", false)
	if _, _, kf, err := bd.Create(ctx, tpmPlan); err != nil || kf != nil {
		t.Fatalf("create: keyfile %v, %v", kf, err)
	}
	var labels []string
	for _, r := range regions(t, img) {
		labels = append(labels, r.Label)
	}
	if !slices.Equal(labels, []string{disk.LabelESP, disk.LabelRootA, disk.LabelRootB, disk.LabelState, disk.LabelBackup}) {
		t.Fatalf("labels %v", labels)
	}
	if _, _, kf, err := bd.Open(ctx); err != nil || kf != nil {
		t.Fatalf("open in TPM mode: keyfile %v, %v", kf, err)
	}
}

func TestOpeningADiskWithoutFirstBootsPartitionsFails(t *testing.T) {
	if _, _, _, err := (&keycustody.BootDisk{Path: installedImage(t)}).Open(ctx); err == nil {
		t.Fatal("opened volumes that aren't there")
	}
}

// A reboot or a factory reset unmounts and closes what first boot mounted.
func TestThePowerControllerClosesTheMountedVolumes(t *testing.T) {
	mounts := "/dev/mapper/sneakers-state " + keycustody.StateTarget + " ext4 rw,nosuid,nodev 0 0\n" +
		"/dev/mapper/sneakers-backup " + keycustody.BackupTarget + " ext4 rw,nosuid,nodev 0 0\n"
	targets, mappings := power.VolumeMounts(mounts)
	if !slices.Equal(targets, []string{keycustody.BackupTarget, keycustody.StateTarget}) || !slices.Equal(mappings, []string{"sneakers-backup", "sneakers-state"}) {
		t.Fatalf("targets %v mappings %v", targets, mappings)
	}
}
