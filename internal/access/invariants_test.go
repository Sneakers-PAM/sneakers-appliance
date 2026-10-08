// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
)

func TestInvariants(t *testing.T) {
	base := stateWithOwner("alice", loginKey(t))
	cases := []struct {
		name string
		mut  func(*access.State)
		code string
	}{
		{"valid", func(*access.State) {}, ""},
		{"an owner without keys", func(s *access.State) { s.Admins[0].Keys = nil }, ""},
		{"no owner who can sign in", func(s *access.State) { s.Admins[0].TOTP = nil }, "ACCESS_LAST_OWNER"},
		{"an invited owner beside one who can sign in", func(s *access.State) {
			s.AddAdmin("bob", access.RoleOwner, "alice", t0)
		}, ""},
		{"an empty roster", func(s *access.State) { s.Quorum.Members = nil }, "ACCESS_QUORUM"},
		{"a roster naming nobody", func(s *access.State) { s.Quorum.Members = []string{"zed"} }, "ACCESS_NAME"},
		{"a root code lifetime of 61 minutes", func(s *access.State) { s.AccessPolicy.RootCodeMinutes = 61 }, "ACCESS_POLICY"},
		{"a root session of 60 minutes", func(s *access.State) { s.AccessPolicy.RootSessionMinutes = 60 }, ""},
		{"a key valid for six years", func(s *access.State) { s.AccessPolicy.SSHKeyValidDays = 6 * 365 }, "ACCESS_POLICY"},
		{"an unknown lockout mode", func(s *access.State) { s.AccessPolicy.LockoutMode = "never" }, "ACCESS_POLICY"},
		{"demote last owner", func(s *access.State) { s.Admins[0].Role = access.RoleAdmin }, "ACCESS_LAST_OWNER"},
		{"login equals recovery", func(s *access.State) {
			s.RecoveryKeys = []access.RecoveryKey{{Key: s.Admins[0].Keys[0].Key}}
		}, "ACCESS_KEY_DUPLICATE"},
		{"two equal recovery keys", func(s *access.State) {
			s.RecoveryKeys = append(s.RecoveryKeys, s.RecoveryKeys[0])
		}, "ACCESS_KEY_DUPLICATE"},
		{"three recovery keys", func(s *access.State) { s.RecoveryKeys = recoveryKeys(t, 3) }, ""},
		{"fourth recovery key", func(s *access.State) { s.RecoveryKeys = recoveryKeys(t, 4) }, "ACCESS_RECOVERY_KEY_LIMIT"},
		{"no recovery key after setup", func(s *access.State) { s.RecoveryKeys = nil }, "ACCESS_LAST_RECOVERY_KEY"},
		{"sk recovery key", func(s *access.State) {
			k, err := access.ParseLoginKey(readFixture(t, genSKEd25519))
			if err != nil {
				t.Fatal(err)
			}
			s.RecoveryKeys = []access.RecoveryKey{{Key: k}}
		}, "ACCESS_KEY_TYPE"},
		{"weak login key", func(s *access.State) {
			s.Admins[0].Keys[0].PublicKey = readFixture(t, "testdata/rsa2048.pub")
		}, "ACCESS_KEY_WEAK"},
		{"reserved name", func(s *access.State) { s.Admins[0].Name = "maint" }, "ACCESS_NAME"},
		{"reserved name console", func(s *access.State) { s.Admins[0].Name = "console" }, "ACCESS_NAME"},
		{"invalid name", func(s *access.State) { s.Admins[0].Name = "Alice" }, "ACCESS_NAME"},
		{"same name twice", func(s *access.State) {
			s.AddAdmin("alice", access.RoleAdmin, "alice", t0)
		}, "ACCESS_NAME"},
		{"same key on two admins", func(s *access.State) {
			b := s.AddAdmin("bob", access.RoleAdmin, "alice", t0)
			b.Keys = s.Admins[0].Keys
		}, "ACCESS_KEY_DUPLICATE"},
		{"unknown role", func(s *access.State) { s.Admins[0].Role = "root" }, "ACCESS_FORBIDDEN"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := base.Clone()
			s.RecoveryKeys = recoveryKeys(t, 1)
			c.mut(&s)
			assertCode(t, access.Check(s, true, true), c.code)
		})
	}
}

func TestInvariantsBeforeTheirSteps(t *testing.T) {
	assertCode(t, access.Check(access.State{}, false, false), "")
	s := stateWithOwner("alice", loginKey(t))
	assertCode(t, access.Check(s, true, false), "")
	assertCode(t, access.Check(s, true, true), "ACCESS_LAST_RECOVERY_KEY")
	assertCode(t, access.Check(access.State{}, true, false), "ACCESS_LAST_OWNER")
}
