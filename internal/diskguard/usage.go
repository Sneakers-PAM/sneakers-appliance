// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package diskguard keeps the box's disk from filling: it watches each
// volume's use with a warning at 80% and a critical alert at 90% (with
// hysteresis, so a level doesn't flap), audits each alert as it starts
// and clears, samples the product's data paths for growth, and runs the
// cleanup that frees space by itself (every hour, and at once when a
// volume passes 80%). The cleanup removes only what it may (allowed
// roots) and never what it mustn't (the safety list), whatever a step
// asks for. docs/disk-layout.md has the design.
package diskguard

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// The levels' thresholds, in percent of a volume used. A level starts at
// its threshold and clears Hysteresis points below it.
const (
	WarnPercent     = 80
	CriticalPercent = 90
	Hysteresis      = 5
)

// Level is a volume's alert level.
type Level int

// The levels, in order.
const (
	LevelOK Level = iota
	LevelWarning
	LevelCritical
)

func (l Level) String() string {
	switch l {
	case LevelWarning:
		return "warning"
	case LevelCritical:
		return "critical"
	}
	return "ok"
}

// NextLevel is the level a volume at pct moves to from cur: up as soon as
// it reaches a threshold, down only once it is Hysteresis points below.
func NextLevel(cur Level, pct float64) Level {
	switch {
	case pct >= CriticalPercent:
		return LevelCritical
	case cur == LevelCritical && pct >= CriticalPercent-Hysteresis:
		return LevelCritical
	case pct >= WarnPercent:
		return LevelWarning
	case cur >= LevelWarning && pct >= WarnPercent-Hysteresis:
		return LevelWarning
	}
	return LevelOK
}

// Usage is a filesystem's size and use.
type Usage struct {
	// Total is the filesystem's size, Used what's in use and Avail what an
	// unprivileged writer may still use (the reserved blocks left out).
	Total, Used, Avail uint64
	// Device identifies the filesystem, so two paths on one volume count
	// once.
	Device uint64
}

// Percent is the share in use as df gives it: used over used plus
// available, so the root-reserved blocks count as full.
func (u Usage) Percent() float64 {
	if u.Used+u.Avail == 0 {
		return 0
	}
	return float64(u.Used) * 100 / float64(u.Used+u.Avail)
}

// Statfs reads the filesystem path is on.
func Statfs(path string) (Usage, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return Usage{}, fmt.Errorf("diskguard: statfs %s: %w", path, err)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return Usage{}, fmt.Errorf("diskguard: stat %s: %w", path, err)
	}
	bs := uint64(fs.Bsize) // #nosec G115 -- a block size is positive
	return Usage{Total: fs.Blocks * bs, Used: (fs.Blocks - fs.Bfree) * bs, Avail: fs.Bavail * bs, Device: st.Dev}, nil
}
