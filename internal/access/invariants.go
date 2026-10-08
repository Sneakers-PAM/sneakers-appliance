// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// Check applies every access invariant of spec 2 Section 4.2 to s.
// adminDone says the first admin exists and setupDone that setup is
// finished: before them, an empty admin list or recovery key list is
// allowed.
func Check(s State, adminDone, setupDone bool) error {
	names := map[string]bool{}
	uids := map[int]bool{}
	seen := map[string]string{}
	owners, ownersWithCredentials := 0, 0
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
			if a.HasCredentials() {
				ownersWithCredentials++
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
	if err := checkPolicy(s.AccessPolicy.Effective()); err != nil {
		return err
	}
	if adminDone {
		if owners == 0 {
			return codes.New(codes.AccessLastOwner, "the box must keep at least one owner")
		}
		if ownersWithCredentials == 0 {
			return codes.New(codes.AccessLastOwner, "the box must keep at least one owner who can sign in")
		}
		if s.Quorum != nil {
			if err := ValidateQuorum(s, *s.Quorum); err != nil {
				return err
			}
		}
	}
	if setupDone && len(s.RecoveryKeys) == 0 {
		return codes.New(codes.AccessLastRecoveryKey, "the last recovery key can't be removed; add its replacement first")
	}
	return nil
}

func checkPolicy(p Policy) error {
	switch p.LockoutMode {
	case LockoutTimed, LockoutUntilUnlocked:
	default:
		return codes.New(codes.AccessPolicy, "the lockout mode is %s or %s, not %q", LockoutTimed, LockoutUntilUnlocked, p.LockoutMode)
	}
	if p.RootCodeMinutes < MinRootMinutes || p.RootCodeMinutes > MaxRootMinutes {
		return codes.New(codes.AccessPolicy, "a root-shell code lasts %d to %d minutes", MinRootMinutes, MaxRootMinutes)
	}
	if p.RootSessionMinutes < MinRootMinutes || p.RootSessionMinutes > MaxRootMinutes {
		return codes.New(codes.AccessPolicy, "a root shell lasts %d to %d minutes", MinRootMinutes, MaxRootMinutes)
	}
	if p.SSHKeyValidDays < MinKeyValidDays || p.SSHKeyValidDays > MaxKeyValidDays {
		return codes.New(codes.AccessPolicy, "an SSH key is valid for %d to %d days", MinKeyValidDays, MaxKeyValidDays)
	}
	return nil
}
