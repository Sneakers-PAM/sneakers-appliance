// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package disk writes the installed disk layout (spec 1 Section 3.2) and
// plans the partitions first boot adds to fill the real disk.
package disk

import (
	"fmt"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/bootcmd"
)

// Sizes and alignment.
const (
	MiB = int64(1) << 20
	GiB = int64(1) << 30

	// Align is the partition alignment.
	Align = MiB
	// SectorSize is the logical sector size written.
	SectorSize = 512
	// GPTTail is the backup GPT at the end of the disk: 32 sectors of
	// entries and the header.
	GPTTail = 33 * SectorSize

	ESPSize     = GiB
	KeyfileSize = 16 * MiB

	// MinDisk is the smallest disk the appliance installs on.
	MinDisk = 64 * GiB
	// MinPiMedia is the smallest Pi SD card or USB disk (32 GB).
	MinPiMedia = 32_000_000_000
)

// GPT partition labels.
const (
	LabelESP     = "ESP"
	LabelRootA   = "sneakers-root-a"
	LabelRootB   = "sneakers-root-b"
	LabelKeyfile = "sneakers-keyfile"
	LabelState   = "sneakers-state"
	LabelBackup  = "sneakers-backup"
)

// GPT partition type GUIDs.
const (
	TypeESP       = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
	TypeRootAMD64 = "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709"
	TypeRootARM64 = "B921B045-1DF0-41C3-AF44-4C6F280D3FAE"
	TypeData      = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
	TypeLUKS      = "CA7D7CCB-63ED-4C53-861C-1742536059CC"
)

// Partition is one planned partition. Start and Size are bytes.
type Partition struct {
	Number int
	Label  string
	Type   string
	Start  int64
	Size   int64
}

// SlotSize is the size of each root slot.
func SlotSize(arch string) int64 {
	if arch == "arm64" {
		return 6 * GiB
	}
	return 8 * GiB
}

// Installed is the layout the kit writes on amd64: partitions 1 to 3.
func Installed() []Partition {
	start := Align
	esp := Partition{Number: 1, Label: LabelESP, Type: TypeESP, Start: start, Size: ESPSize}
	a := Partition{Number: 2, Label: LabelRootA, Type: TypeRootAMD64, Start: esp.Start + esp.Size, Size: SlotSize("amd64")}
	b := Partition{Number: 3, Label: LabelRootB, Type: TypeRootAMD64, Start: a.Start + a.Size, Size: SlotSize("amd64")}
	return []Partition{esp, a, b}
}

// InstalledBytes is where the kit's partitions end and first boot's begin.
func InstalledBytes(arch string) int64 {
	if arch == "arm64" {
		// Pi: autoboot 64 MiB, boot-a and boot-b 256 MiB each, then the two
		// root slots, after the 1 MiB GPT head.
		return Align + 64*MiB + 2*256*MiB + 2*SlotSize("arm64")
	}
	p := Installed()
	last := p[len(p)-1]
	return last.Start + last.Size
}

// FirstBootPlan lays out the partitions first boot creates in the space
// after used on a disk of diskSize bytes: the key file (only when keyfile
// is set), state, and backup at the end. Backup gets 30% of the free space,
// at least 16 GiB (4 GiB on the Pi); state gets the rest, so no space is
// stranded however large the disk is.
func FirstBootPlan(diskSize, used int64, arch string, keyfile bool) ([]Partition, error) {
	minBackup, first := 16*GiB, 4
	if arch == "arm64" {
		minBackup, first = 4*GiB, 6
		keyfile = true // the Pi has no TPM: always key-file mode
	}
	end := diskSize - GPTTail
	free := end - used
	need := minBackup + Align
	if keyfile {
		need += KeyfileSize
	}
	if free < need {
		return nil, fmt.Errorf("disk: %d bytes free after the installed partitions; first boot needs at least %d", free, need)
	}
	var out []Partition
	start, n := used, first
	if keyfile {
		out = append(out, Partition{Number: n, Label: LabelKeyfile, Type: TypeData, Start: start, Size: KeyfileSize})
		start += KeyfileSize
		n++
	}
	// Backup takes the end of the disk from an aligned start, so it gets
	// at least its share plus the unaligned tail.
	backup := max(free*30/100, minBackup)
	backupStart := (end - backup) / Align * Align
	state := backupStart - start
	if state < Align {
		return nil, fmt.Errorf("disk: no room for the state partition")
	}
	out = append(out,
		Partition{Number: n, Label: LabelState, Type: TypeLUKS, Start: start, Size: state},
		Partition{Number: n + 1, Label: LabelBackup, Type: TypeLUKS, Start: backupStart, Size: end - backupStart},
	)
	return out, nil
}

// SlotGUID is the PARTUUID a root slot gets; see bootcmd.SlotGUID, which
// switchroot uses to find it again.
func SlotGUID(rootHash string) (string, error) { return bootcmd.SlotGUID(rootHash) }
