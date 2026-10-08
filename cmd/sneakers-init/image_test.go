// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	log "github.com/Bugs5382/go-log"
	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/partition/gpt"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/switchroot"
)

const (
	runningGUID = "11111111-2222-3333-4444-555555555555"
	newGUID     = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

func installedDisk(t *testing.T) string {
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

func guidOf(t *testing.T, img, label string) string {
	t.Helper()
	d, err := diskfs.Open(img, diskfs.WithOpenMode(diskfs.ReadOnly))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	tbl, err := d.GetPartitionTable()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range tbl.(*gpt.Table).Partitions {
		if p.Name == label {
			return p.GUID
		}
	}
	t.Fatalf("no %s", label)
	return ""
}

func TestSlotsWriteTheInactiveSlotAndSetItsPartUUID(t *testing.T) {
	img := installedDisk(t)
	slotB := filepath.Join(t.TempDir(), "vda3")
	if err := os.WriteFile(slotB, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &gptSlots{disk: img, running: runningGUID, log: log.Nop(), list: func() ([]switchroot.Partition, error) {
		return []switchroot.Partition{
			{Device: "/dev/vda1", Label: disk.LabelESP},
			{Device: "/dev/vda2", Label: switchroot.LabelRootA, PartUUID: strings.ToUpper(runningGUID)},
			{Device: slotB, Label: switchroot.LabelRootB, PartUUID: "00000000-0000-0000-0000-000000000003"},
		}, nil
	}}
	root := bytes.Repeat([]byte("r"), 4096)
	if err := s.WriteInactive(context.Background(), bytes.NewReader(root), int64(len(root)), newGUID); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(slotB); !bytes.Equal(b, root) {
		t.Fatalf("slot B holds %d bytes", len(b))
	}
	if g := guidOf(t, img, switchroot.LabelRootB); !strings.EqualFold(g, newGUID) {
		t.Fatalf("slot B PARTUUID %s", g)
	}
}

func TestSlotsRefuseWhenTheRunningSlotIsUnknown(t *testing.T) {
	s := &gptSlots{disk: "unused", running: runningGUID, log: log.Nop(), list: func() ([]switchroot.Partition, error) {
		return []switchroot.Partition{
			{Device: "/dev/vda2", Label: switchroot.LabelRootA, PartUUID: "00000000-0000-0000-0000-000000000002"},
			{Device: "/dev/vda3", Label: switchroot.LabelRootB, PartUUID: "00000000-0000-0000-0000-000000000003"},
		}, nil
	}}
	if err := s.WriteInactive(context.Background(), bytes.NewReader(nil), 0, newGUID); err == nil {
		t.Fatal("wrote a slot without knowing which one the box runs from")
	}
}

func TestDirESPWritesRenamesAndRemoves(t *testing.T) {
	e := dirESP{root: t.TempDir()}
	if err := e.WriteFile("EFI/Linux/a.efi", strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	if err := e.Rename("EFI/Linux/a.efi", "EFI/Linux/b.efi"); err != nil {
		t.Fatal(err)
	}
	if got, err := e.List("EFI/Linux"); err != nil || len(got) != 1 || got[0] != "b.efi" {
		t.Fatalf("%v %v", got, err)
	}
	if err := e.Remove("EFI/Linux/b.efi"); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.List("EFI/missing"); got != nil {
		t.Fatal(got)
	}
}
