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

// checkRoom refuses a move that won't fit, from the real sizes, before the
// services stop. Two paths on one filesystem count once.
func checkRoom(disk func(string) (Usage, error), backup, volumes string, data int64) error {
	dump, volume := roomFor(data)
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
			return codes.New(codes.DataMoveRoom, "the move needs %s free on %s and there's %s", gibs(need), backup, gibs(bu.Avail))
		}
		return nil
	}
	if bu.Avail < dump {
		return codes.New(codes.DataMoveRoom, "the move's dump needs %s free on %s and there's %s", gibs(dump), backup, gibs(bu.Avail))
	}
	if vu.Avail < volume {
		return codes.New(codes.DataMoveRoom, "the new database needs %s free on %s and there's %s", gibs(volume), volumes, gibs(vu.Avail))
	}
	return nil
}
