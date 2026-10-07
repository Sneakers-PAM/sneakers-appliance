// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package imageupgrade stages a release into the inactive root slot and
// manages the systemd-boot entries that boot it (spec 1 Sections 2.6 and
// 3.1): it verifies before writing, writes durably and keeps the previous
// release, with systemd-boot boot counting and A/B root partitions.
package imageupgrade

import (
	"fmt"
	"regexp"
	"strconv"
)

// UKIDir is where the entries live on the ESP.
const UKIDir = "EFI/Linux"

// Tries is how many boots a newly staged release gets before systemd-boot
// falls back.
const Tries = 3

var entryRE = regexp.MustCompile(`^sneakers-([0-9][0-9A-Za-z.\-]*?)(?:\+([0-9]+)(?:-([0-9]+))?)?\.efi$`)

// EntryName is the ESP file name of a UKI with a boot counter: left tries
// remain, done have been used.
func EntryName(version string, left, done int) string {
	return fmt.Sprintf("sneakers-%s+%d-%d.efi", version, left, done)
}

// GoodName is the name of an entry without a counter: known good.
func GoodName(version string) string { return "sneakers-" + version + ".efi" }

// Entry is a parsed ESP entry name.
type Entry struct {
	Name    string
	Version string
	// Counted: the name carries a boot counter.
	Counted    bool
	Left, Done int
}

// Bad reports a counted entry with no tries left: systemd-boot sorts it
// last, so the box boots something else.
func (e Entry) Bad() bool { return e.Counted && e.Left == 0 }

// ParseEntry reads an entry name.
func ParseEntry(name string) (Entry, bool) {
	m := entryRE.FindStringSubmatch(name)
	if m == nil {
		return Entry{}, false
	}
	e := Entry{Name: name, Version: m[1]}
	if m[2] != "" {
		e.Counted = true
		e.Left, _ = strconv.Atoi(m[2])
		if m[3] != "" {
			e.Done, _ = strconv.Atoi(m[3])
		}
	}
	return e, true
}
