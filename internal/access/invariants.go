// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Check applies every access invariant of spec 2 Section 4.2 to s.
// step3Done and step4Done say whether the first admin and the recovery key
// setup steps have completed: before them, an empty admin list or recovery
// key list is allowed.
func Check(s State, step3Done, step4Done bool) error {
	names := map[string]bool{}
	uids := map[int]bool{}
	seen := map[string]string{}
	owners, ownersWithKey := 0, 0
	for _, a := range s.Admins {
		if !ValidName(a.Name) {
			return codes.New(codes.AccessName, "%q isn't a valid admin name: use 2 to 31 lowercase letters, digits, _ or -, starting with a letter, and not a reserved name", a.Name)
		}
		if names[a.Name] {
			return codes.New(codes.AccessName, "there is already an admin named %q", a.Name)
		}
		names[a.Name] = true
		if a.UID < FirstUID || uids[a.UID] {
			return codes.New(codes.AccessName, "admin %q has uid %d, which is outside the admin range or taken", a.Name, a.UID)
		}
		uids[a.UID] = true
		switch a.Role {
		case RoleOwner:
			owners++
			if len(a.Keys) > 0 {
				ownersWithKey++
			}
		case RoleAdmin:
		default:
			return codes.New(codes.AccessForbidden, "admin %q has an unknown role %q", a.Name, a.Role)
		}
		for _, k := range a.Keys {
			parsed, err := ParseLoginKey(k.PublicKey)
			if err != nil {
				return err
			}
			if who, dup := seen[parsed.Fingerprint]; dup {
				return codes.New(codes.AccessKeyDuplicate, "key %s is already a key of %s", parsed.Fingerprint, who)
			}
			if s.revoked(parsed.Fingerprint) {
				return codes.New(codes.AccessKeyRevoked, "key %s was removed and is revoked; an owner must un-revoke it before it's added again", parsed.Fingerprint)
			}
			seen[parsed.Fingerprint] = "admin " + a.Name
		}
	}
	if len(s.RecoveryKeys) > MaxRecoveryKeys {
		return codes.New(codes.AccessRecoveryKeyLimit, "a box holds at most %d recovery keys", MaxRecoveryKeys)
	}
	for _, r := range s.RecoveryKeys {
		parsed, err := ParseRecoveryKey(r.PublicKey)
		if err != nil {
			return err
		}
		if who, dup := seen[parsed.Fingerprint]; dup {
			return codes.New(codes.AccessKeyDuplicate, "key %s is already a key of %s; a recovery key must differ from every login key and every other recovery key", parsed.Fingerprint, who)
		}
		seen[parsed.Fingerprint] = "a recovery key"
	}
	if step3Done {
		if owners == 0 {
			return codes.New(codes.AccessLastOwner, "the box must keep at least one owner")
		}
		if ownersWithKey == 0 {
			return codes.New(codes.AccessLastKey, "the last key of the last owner can't be removed; add the new key first")
		}
	}
	if step4Done && len(s.RecoveryKeys) == 0 {
		return codes.New(codes.AccessLastRecoveryKey, "the last recovery key can't be removed; add its replacement first")
	}
	return nil
}
