// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package disk_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
)

// TestFirstBootPlanFillsGrownDisk pins Review Focus 4: an OVA disk grown
// before the first power-on, or a bigger bare disk, ends up in state and
// backup, with nothing stranded.
func TestFirstBootPlanFillsGrownDisk(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		minBackup := 16 * disk.GiB
		sizes := []int64{64, 100, 2048}
		if arch == "arm64" {
			minBackup, sizes = 4*disk.GiB, []int64{30, 64, 512}
		}
		for _, keyfile := range []bool{true, false} {
			for _, gib := range sizes {
				size := gib<<30 + 12345*512 // not a whole number of MiB
				used := disk.InstalledBytes(arch)
				p, err := disk.FirstBootPlan(size, used, arch, keyfile)
				if err != nil {
					t.Fatalf("%s %d GiB: %v", arch, gib, err)
				}
				free := size - used - disk.GPTTail
				backup, state := p[len(p)-1], p[len(p)-2]
				if backup.Size < minBackup || backup.Size < free*30/100 {
					t.Errorf("%s %d GiB: backup %d", arch, gib, backup.Size)
				}
				var sum int64
				for i, q := range p {
					sum += q.Size
					if q.Start%disk.Align != 0 {
						t.Errorf("%s %d GiB: partition %d starts unaligned", arch, gib, q.Number)
					}
					if i > 0 && p[i-1].Start+p[i-1].Size != q.Start {
						t.Errorf("%s %d GiB: gap before %d", arch, gib, q.Number)
					}
				}
				if sum != free || backup.Start+backup.Size != size-disk.GPTTail {
					t.Errorf("%s %d GiB: %d of %d bytes used", arch, gib, sum, free)
				}
				if state.Label != disk.LabelState || backup.Label != disk.LabelBackup {
					t.Errorf("labels %s %s", state.Label, backup.Label)
				}
				wantKeyfile := keyfile || arch == "arm64"
				if (p[0].Label == disk.LabelKeyfile) != wantKeyfile {
					t.Errorf("%s keyfile=%v: first is %s", arch, keyfile, p[0].Label)
				}
				first := 4
				if arch == "arm64" {
					first = 6
				}
				if p[0].Number != first {
					t.Errorf("%s: first partition %d", arch, p[0].Number)
				}
			}
		}
	}
}

func TestFirstBootPlanRefusesATinyDisk(t *testing.T) {
	if _, err := disk.FirstBootPlan(20*disk.GiB, disk.InstalledBytes("amd64"), "amd64", true); err == nil {
		t.Fatal("20 GiB can't hold the installed layout and a backup")
	}
}

func TestSlotGUID(t *testing.T) {
	g, err := disk.SlotGUID("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err != nil || g != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatalf("%s %v", g, err)
	}
}
