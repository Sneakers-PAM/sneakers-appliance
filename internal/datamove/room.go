// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package datamove

import (
	"fmt"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

const (
	gibibyte = int64(1) << 30
	// walRoom is what the new cluster's write-ahead log may take while it
	// restores, on top of the data itself.
	walRoom = gibibyte
	// dumpPercent is the dump's room as a share of the data. Measured
	// dumps came to 30%; the margin covers data that compresses less.
	dumpPercent = 35
	// dumpFloor is the smallest room asked for a dump, for a small box
	// whose dump is mostly overhead.
	dumpFloor = 64 << 20
)

// roomFor is what a move of data bytes needs: for the dump, and for the
// target's volume.
func roomFor(data int64) (dump, volume uint64) {
	d := data / 100 * dumpPercent
	if d < dumpFloor {
		d = dumpFloor
	}
	return uint64(d), uint64(data + walRoom) // #nosec G115 -- sizes are positive
}

func gibs(n uint64) string { return fmt.Sprintf("%.1f GiB", float64(n)/float64(gibibyte)) }

// returnRoom is what a return needs, from each database's size on the old
// cluster and on the target, in the order they restore. The dump gets the
// kept dump's room as well when there's one to write. A database's files go
// from the target before its new copy goes in, so the volume only needs what
// the restore grows past that at its fullest.
func returnRoom(old, target []int64, keep bool) (dump, volume uint64) {
	var oldSum, targetSum, peak, grown int64
	for i := range old {
		oldSum += old[i]
		targetSum += target[i]
		grown += old[i] - target[i]
		peak = max(peak, grown)
	}
	dump, _ = roomFor(oldSum)
	if keep {
		kept, _ := roomFor(targetSum)
		dump += kept
	}
	return dump, uint64(peak + walRoom) // #nosec G115 -- peak is 0 or more
}

// checkRoom refuses a move that won't fit, from the real sizes, before the
// services stop. Two paths on one filesystem count once. hint ends a refusal.
func checkRoom(disk func(string) (Usage, error), backup, volumes string, dump, volume uint64, hint string) error {
	bu, err := disk(backup)
	if err != nil {
		return fmt.Errorf("reading the backup partition: %w", err)
	}
	vu, err := disk(volumes)
	if err != nil {
		return fmt.Errorf("reading the data volume: %w", err)
	}
	if bu.Device == vu.Device {
		if need := dump + volume; bu.Avail < need {
			return codes.New(codes.DataMoveRoom, "the move needs %s free on %s and there's %s%s", gibs(need), backup, gibs(bu.Avail), hint)
		}
		return nil
	}
	if bu.Avail < dump {
		return codes.New(codes.DataMoveRoom, "the move's dump needs %s free on %s and there's %s%s", gibs(dump), backup, gibs(bu.Avail), hint)
	}
	if vu.Avail < volume {
		return codes.New(codes.DataMoveRoom, "the new database needs %s free on %s and there's %s%s", gibs(volume), volumes, gibs(vu.Avail), hint)
	}
	return nil
}
