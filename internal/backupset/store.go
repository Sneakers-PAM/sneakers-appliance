// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package backupset cuts backup sets from the archive a product's database
// keeps on the backup partition, restores one, and holds a stuck archive from
// filling the data volume (docs/backups.md). The appliance names no chart:
// product.yaml's backups declare everything.
package backupset

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The store's layout, which is WAL-G's file backend.
const (
	baseDir = "basebackups_005"
	walDir  = "wal_005"
	// sentinelSuffix ends the file a finished base backup writes last.
	sentinelSuffix = "_backup_stop_sentinel.json"
	// segmentBytes is PostgreSQL's WAL segment size; the charts this
	// works with don't change it.
	segmentBytes = 16 << 20
)

// base is one finished base backup.
type base struct {
	Name         string
	Timeline     uint32
	StartLSN     uint64
	Finished     time.Time
	PGVersion    int
	SystemID     uint64
	Uncompressed int64
}

var baseNameRE = regexp.MustCompile(`^base_([0-9A-F]{8})[0-9A-F]{16}$`)

// bases reads the finished base backups in store, oldest first. One still
// being written has no sentinel, and doesn't count.
func bases(store string) ([]base, error) {
	ents, err := os.ReadDir(filepath.Join(store, baseDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []base
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), sentinelSuffix)
		if !ok {
			continue
		}
		m := baseNameRE.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(store, baseDir, e.Name())) // #nosec G304 -- a name listed from the box's own store
		if err != nil {
			return nil, err
		}
		var s struct {
			LSN              uint64    `json:"LSN"`
			PgVersion        int       `json:"PgVersion"`
			SystemIdentifier uint64    `json:"SystemIdentifier"`
			UncompressedSize int64     `json:"UncompressedSize"`
			FinishTime       time.Time `json:"FinishTime"`
		}
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("the sentinel of %s doesn't read: %w", name, err)
		}
		tl, _ := strconv.ParseUint(m[1], 16, 32)
		out = append(out, base{Name: name, Timeline: uint32(tl), StartLSN: s.LSN, Finished: s.FinishTime, PGVersion: s.PgVersion, SystemID: s.SystemIdentifier, Uncompressed: s.UncompressedSize}) // #nosec G115 -- parsed as 32 bits
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Finished.Before(out[j].Finished) })
	return out, nil
}

// parseLSN reads PostgreSQL's X/Y.
func parseLSN(s string) (uint64, error) {
	hi, lo, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return 0, fmt.Errorf("%q isn't an LSN", s)
	}
	h, err := strconv.ParseUint(hi, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("%q isn't an LSN", s)
	}
	l, err := strconv.ParseUint(lo, 16, 32)
	if err != nil {
		return 0, fmt.Errorf("%q isn't an LSN", s)
	}
	return h<<32 | l, nil
}

// segmentNo is the number of the WAL segment holding lsn.
func segmentNo(lsn uint64) uint64 { return lsn / segmentBytes }

// segmentName is a segment's file name on a timeline.
func segmentName(tl uint32, no uint64) string {
	perLogID := uint64(1<<32) / segmentBytes
	return fmt.Sprintf("%08X%08X%08X", tl, no/perLogID, no%perLogID)
}

// segments maps each archived WAL file's bare name to its name in the
// store. A file still being written ends in .tmp.<stamp>, and doesn't count.
func segments(store string) (map[string]string, error) {
	ents, err := os.ReadDir(filepath.Join(store, walDir))
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(ents))
	for _, e := range ents {
		n := e.Name()
		if strings.Contains(n, tmpMark) {
			continue
		}
		// A .backup history file carries its segment's name too; it isn't
		// the segment.
		if bare, _, _ := strings.Cut(n, "."); len(bare) == 24 && strings.Count(n, ".") == 1 {
			out[bare] = n
		}
	}
	return out, nil
}

// tmpMark is in the name of a WAL file WAL-G hasn't finished. On a full
// partition it leaves them behind.
const tmpMark = ".tmp."

// chain lists the store's WAL files from b's first segment through the one
// holding point, on the timeline, or names the first one missing.
func chain(have map[string]string, b base, tl uint32, point uint64) ([]string, error) {
	if tl != b.Timeline {
		return nil, fmt.Errorf("the base backup %s is on timeline %d and the point on %d", b.Name, b.Timeline, tl)
	}
	var out []string
	for no := segmentNo(b.StartLSN); no <= segmentNo(point); no++ {
		name := segmentName(tl, no)
		f, ok := have[name]
		if !ok {
			return nil, fmt.Errorf("%s isn't in the archive", name)
		}
		out = append(out, f)
	}
	return out, nil
}
