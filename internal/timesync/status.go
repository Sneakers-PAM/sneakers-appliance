// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package timesync

import "time"

// State is the engine's sync state.
type State int

// The states.
const (
	// StateNotConfigured: no time server; the box runs on its hardware
	// clock.
	StateNotConfigured State = iota
	// StatePending: servers are set and the first sync hasn't finished.
	StatePending
	// StateSynced: the last round adjusted the clock.
	StateSynced
	// StateUnsynced: the last round didn't (no reply, disagreement, or a
	// refused step).
	StateUnsynced
)

func (s State) String() string {
	switch s {
	case StatePending:
		return "PENDING"
	case StateSynced:
		return "SYNCED"
	case StateUnsynced:
		return "UNSYNCED"
	default:
		return "NOT_CONFIGURED"
	}
}

// Source is where the servers came from.
type Source int

// The sources.
const (
	SourceNone Source = iota
	// SourceSettings: the admin's network settings.
	SourceSettings
	// SourceDHCP: DHCPv4 option 42 or DHCPv6 option 56.
	SourceDHCP
	// SourceDefault: the image's default pool, used while neither the
	// settings nor DHCP name a server.
	SourceDefault
)

// Status is the engine's state for netd's Status and the NTP check.
type Status struct {
	State         State
	Source        Source
	Servers       []string
	LastServer    string
	Stratum       uint32
	SteppedAtBoot bool
	LastError     string
	// LastOffset is the last measured offset, when HasOffset.
	LastOffset time.Duration
	HasOffset  bool
	LastSync   time.Time
}

func (s Source) String() string {
	switch s {
	case SourceSettings:
		return "SETTINGS"
	case SourceDHCP:
		return "DHCP"
	case SourceDefault:
		return "DEFAULT"
	default:
		return "NONE"
	}
}
