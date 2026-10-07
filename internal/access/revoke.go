// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"fmt"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"
)

// RevokedKey is a login key that was removed from an admin, or went with
// its admin. It stays on sshd's revocation list until an owner un-revokes
// it, and can't be added to any admin meanwhile.
type RevokedKey struct {
	Fingerprint string    `json:"fingerprint"`
	PublicKey   string    `json:"publicKey"`
	Admin       string    `json:"admin"`
	Revoked     time.Time `json:"revoked"`
}

// revokeRemoved appends every login key cur has and next doesn't to next's
// revoked keys: whichever call removed a key or an admin, the key is revoked
// in the same write.
func revokeRemoved(cur State, next *State, now time.Time) {
	kept := map[string]bool{}
	for _, a := range next.Admins {
		for _, k := range a.Keys {
			kept[k.Fingerprint] = true
		}
	}
	for _, a := range cur.Admins {
		for _, k := range a.Keys {
			if kept[k.Fingerprint] || next.revoked(k.Fingerprint) {
				continue
			}
			next.RevokedKeys = append(next.RevokedKeys, RevokedKey{Fingerprint: k.Fingerprint, PublicKey: k.PublicKey, Admin: a.Name, Revoked: now.UTC()})
		}
	}
}

func (s *State) revoked(fp string) bool {
	return slices.ContainsFunc(s.RevokedKeys, func(r RevokedKey) bool { return r.Fingerprint == fp })
}

// Unrevoke takes fp off the revoked keys, so it may be added again; false
// when it wasn't revoked.
func (s *State) Unrevoke(fp string) bool {
	n := len(s.RevokedKeys)
	s.RevokedKeys = slices.DeleteFunc(s.RevokedKeys, func(r RevokedKey) bool { return r.Fingerprint == fp })
	return len(s.RevokedKeys) < n
}

// RevokedPublicKeys parses the revoked keys for the revocation list.
func (s State) RevokedPublicKeys() ([]ssh.PublicKey, error) {
	out := make([]ssh.PublicKey, 0, len(s.RevokedKeys))
	for _, r := range s.RevokedKeys {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(r.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("access: revoked key %s doesn't parse: %w", r.Fingerprint, err)
		}
		out = append(out, pk)
	}
	return out, nil
}
