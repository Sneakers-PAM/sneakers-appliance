// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"slices"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
)

func admins(names ...string) access.State {
	var s access.State
	for _, n := range names {
		s.AddAdmin(n, access.RoleOwner, "console", t0)
	}
	return s
}

func TestTheDefaultQuorumIsTwoOfEveryAdmin(t *testing.T) {
	q := admins("alice", "bob", "carol").EffectiveQuorum()
	if !slices.Equal(q.Members, []string{"alice", "bob", "carol"}) || q.Required != 2 || q.Configured || !q.Available() {
		t.Fatalf("%+v", q)
	}
}

func TestASingleAdminHasNoQuorum(t *testing.T) {
	q := admins("alice").EffectiveQuorum()
	if q.Available() {
		t.Fatalf("%+v", q)
	}
}

func TestAConfiguredRosterFollowsAdminsWhoLeave(t *testing.T) {
	s := admins("alice", "bob", "carol", "dave")
	s.Quorum = &access.QuorumRoster{Members: []string{"alice", "bob", "carol"}, Required: 3}
	q := s.EffectiveQuorum()
	if !q.Configured || q.Required != 3 || len(q.Members) != 3 {
		t.Fatalf("%+v", q)
	}
	s.Admins = slices.DeleteFunc(s.Admins, func(a access.Admin) bool { return a.Name == "carol" })
	q = s.EffectiveQuorum()
	if !slices.Equal(q.Members, []string{"alice", "bob"}) || q.Required != 2 || !q.Available() {
		t.Fatalf("the threshold recomputes when a member leaves: %+v", q)
	}
	s.Admins = slices.DeleteFunc(s.Admins, func(a access.Admin) bool { return a.Name == "bob" })
	if s.EffectiveQuorum().Available() {
		t.Fatal("one member left is no quorum")
	}
}

func TestValidateQuorum(t *testing.T) {
	s := admins("alice", "bob", "carol")
	for _, tc := range []struct {
		members  []string
		required int
		ok       bool
	}{
		{[]string{"alice", "bob"}, 2, true},
		{[]string{"alice", "bob", "carol"}, 2, true},
		{[]string{"alice"}, 1, true},
		{nil, 0, false},
		{[]string{"alice", "bob"}, 1, false},
		{[]string{"alice", "bob"}, 3, false},
		{[]string{"alice", "alice"}, 2, false},
		{[]string{"alice", "zed"}, 2, false},
	} {
		err := access.ValidateQuorum(s, access.QuorumRoster{Members: tc.members, Required: tc.required})
		if (err == nil) != tc.ok {
			t.Errorf("%v of %v: %v", tc.required, tc.members, err)
		}
	}
}

func TestRootOperatorsAreTheRoster(t *testing.T) {
	s := admins("alice", "bob")
	s.Quorum = &access.QuorumRoster{Members: []string{"alice"}, Required: 1}
	if !s.IsRootOperator("alice") || s.IsRootOperator("bob") {
		t.Fatalf("root operators %v", s.RootOperators())
	}
}

func TestCloneCopiesTheRoster(t *testing.T) {
	s := admins("alice", "bob")
	s.Quorum = &access.QuorumRoster{Members: []string{"alice", "bob"}, Required: 2}
	c := s.Clone()
	c.Quorum.Members[0] = "x"
	if s.Quorum.Members[0] != "alice" {
		t.Fatal("deep copy")
	}
}
