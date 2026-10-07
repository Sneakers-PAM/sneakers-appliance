// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"slices"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// QuorumRoster is the owner-set factory-reset quorum: the admins whose
// approvals count and how many must approve (spec 2, Section 2.12).
type QuorumRoster struct {
	Members  []string `json:"members"`
	Required int      `json:"required"`
}

// Quorum is the roster in force.
type Quorum struct {
	Members    []string
	Required   int
	Configured bool
}

// Available reports whether a factory reset can reach its quorum: at least
// two members and a threshold of at least two. A box with one admin never
// has one.
func (q Quorum) Available() bool { return len(q.Members) >= 2 && q.Required >= 2 }

// EffectiveQuorum is the roster in force. Unset, it is every admin with
// two approvals. Set, members who are no longer admins drop out and the
// threshold drops with them, so the quorum keeps working after an admin
// leaves.
func (s State) EffectiveQuorum() Quorum {
	if s.Quorum == nil {
		var all []string
		for _, a := range s.Admins {
			all = append(all, a.Name)
		}
		return Quorum{Members: all, Required: min(2, len(all))}
	}
	var live []string
	for _, m := range s.Quorum.Members {
		if _, ok := s.Admin(m); ok {
			live = append(live, m)
		}
	}
	return Quorum{Members: live, Required: min(s.Quorum.Required, len(live)), Configured: true}
}

// ValidateQuorum checks a roster an owner sets: distinct current admins,
// at least two of them, and a threshold from two to the roster's size.
func ValidateQuorum(s State, r QuorumRoster) error {
	seen := map[string]bool{}
	for _, m := range r.Members {
		if _, ok := s.Admin(m); !ok {
			return codes.New(codes.AccessName, "there is no admin named %q", m)
		}
		if seen[m] {
			return codes.New(codes.AccessName, "%q is on the roster twice", m)
		}
		seen[m] = true
	}
	if len(r.Members) < 2 {
		return codes.New(codes.ResetUnavailable, "a quorum needs at least two admins on its roster")
	}
	if r.Required < 2 || r.Required > len(r.Members) {
		return codes.New(codes.ResetUnavailable, "the threshold must be from 2 to %d, the roster's size", len(r.Members))
	}
	return nil
}

func (r *QuorumRoster) clone() *QuorumRoster {
	if r == nil {
		return nil
	}
	return &QuorumRoster{Members: slices.Clone(r.Members), Required: r.Required}
}
