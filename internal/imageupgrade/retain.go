// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package imageupgrade

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/mod/semver"
)

// MaxKeep is the most releases a box keeps. The boot disk has two root
// partitions, one release in each; keeping more needs an image with more
// root partitions.
const MaxKeep = 2

// DefaultKeep is how many releases a box keeps when Stager.Keep is unset:
// the running one and the one before it, for a revert.
const DefaultKeep = 2

// Retain is the retention rule, keep n and drop the oldest. Of entries it
// keeps the running release's and the newest n-2 others, so a release
// staged next makes n; good entries are kept before bad ones. It returns
// the entries to remove, oldest first.
func Retain(entries []Entry, running string, n int) []Entry {
	var others []Entry
	for _, e := range entries {
		if e.Version != running {
			others = append(others, e)
		}
	}
	sort.SliceStable(others, func(i, j int) bool {
		if others[i].Bad() != others[j].Bad() {
			return !others[i].Bad()
		}
		return semver.Compare("v"+others[i].Version, "v"+others[j].Version) > 0
	})
	room := max(n-2, 0)
	if room >= len(others) {
		return []Entry{}
	}
	drop := others[room:]
	sort.SliceStable(drop, func(i, j int) bool {
		return semver.Compare("v"+drop[i].Version, "v"+drop[j].Version) < 0
	})
	return drop
}

// Keeps is how many releases the box keeps: Keep, defaulted and held
// between two (the running release and the staged or previous one share
// the two root partitions) and MaxKeep.
func (s *Stager) Keeps() int {
	switch {
	case s.Keep == 0:
		return DefaultKeep
	case s.Keep < 2:
		return 2
	case s.Keep > MaxKeep:
		return MaxKeep
	}
	return s.Keep
}

// NextStageRemoves names the releases the next Stage removes, with their
// boot entries and everything else tied only to them.
func (s *Stager) NextStageRemoves() ([]string, error) {
	entries, err := s.entries()
	if err != nil {
		return nil, err
	}
	return versionsOf(Retain(entries, s.Running, s.Keeps())), nil
}

func versionsOf(es []Entry) []string {
	out := []string{}
	for _, e := range es {
		out = append(out, e.Version)
	}
	return out
}

// tidyESP removes the .tmp files an ESP write cut off before its rename
// left in the entries' and the loader's directories.
func (s *Stager) tidyESP() error {
	for _, dir := range []string{UKIDir, path.Dir(RevertedFile)} {
		names, err := s.ESP.List(dir)
		if err != nil {
			return err
		}
		for _, n := range names {
			if !strings.HasSuffix(n, ".tmp") {
				continue
			}
			s.logger().Info("imageupgrade: removing a cut-off ESP write", log.F("file", path.Join(dir, n)))
			if err := s.ESP.Remove(path.Join(dir, n)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// tidyWork empties the work directory: a fetched release is needed only
// while it's staged, and its root and UKI are in the slot and on the ESP
// once it is.
func (s *Stager) tidyWork() {
	if s.WorkDir == "" {
		return
	}
	ents, err := os.ReadDir(s.WorkDir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.logger().Warn("imageupgrade: the work directory doesn't read", log.F("error", err.Error()))
		}
		return
	}
	for _, e := range ents {
		p := filepath.Join(s.WorkDir, e.Name())
		if err := os.RemoveAll(p); err != nil {
			s.logger().Warn("imageupgrade: a fetched release wasn't removed", log.F("dir", p), log.F("error", err.Error()))
			continue
		}
		s.logger().Debug("imageupgrade: removed a fetched release", log.F("dir", e.Name()))
	}
}

func (s *Stager) removeEntries(drop []Entry) error {
	for _, e := range drop {
		s.logger().Info("imageupgrade: removing an older release", log.F("version", e.Version), log.F("entry", e.Name))
		if err := s.ESP.Remove(path.Join(UKIDir, e.Name)); err != nil {
			return fmt.Errorf("imageupgrade: remove %s: %w", e.Name, err)
		}
	}
	return nil
}
