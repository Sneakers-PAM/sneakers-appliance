// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"regexp"
	"slices"
	"time"
)

// Role is an admin's role.
type Role string

// The two roles (spec 2, Section 2.6). Root operators are a roster
// (State.RootOperators), not a role.
const (
	// RoleOwner can do everything, including managing admins and the access
	// settings.
	RoleOwner Role = "owner"
	// RoleAdmin can do everything except managing other admins and the
	// access settings.
	RoleAdmin Role = "admin"
)

// ViaIssued marks a key the box made (IssueSshKey); it is the only way a
// login key reaches the store.
const ViaIssued = "issued"

// FirstUID is the uid of the first admin; uids count up from it and are
// never reused.
const FirstUID = 20000

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,30}$`)

// ReservedNames are the system accounts an admin can't be named after.
// console is the OS audit log's actor name for the console; an admin by that
// name would make audit entries ambiguous.
var ReservedNames = []string{"root", "maint", "enrol", "sshd", "sshkeys", "nobody", "osadmin", "console", "setup"}

// ValidName reports whether name may be an admin's name.
func ValidName(name string) bool {
	return namePattern.MatchString(name) && !slices.Contains(ReservedNames, name)
}

// AdminKey is one of an admin's SSH keys: one the box issued, with the
// root-key-signed certificate sshd checks.
type AdminKey struct {
	Key
	Added    time.Time  `json:"added"`
	AddedBy  string     `json:"addedBy"`
	Via      string     `json:"via"`
	LastUsed *time.Time `json:"lastUsed,omitempty"`
	// Serial is the certificate's serial; ValidBefore its end.
	Serial      uint64     `json:"serial,omitempty"`
	ValidBefore *time.Time `json:"validBefore,omitempty"`
	// Certificate is the OpenSSH certificate line.
	Certificate string `json:"certificate,omitempty"`
}

// Password is an admin's stored password.
type Password struct {
	// Hash is argon2id over the password keyed with the box's pepper.
	Hash    string    `json:"hash"`
	Changed time.Time `json:"changed"`
}

// TOTP is an admin's authenticator secret, sealed under the pepper.
type TOTP struct {
	Sealed string    `json:"sealed"`
	Added  time.Time `json:"added"`
}

// Invite is an open invitation: the code's hash, so the store never holds
// a code that still works.
type Invite struct {
	CodeHash string    `json:"codeHash"`
	Expires  time.Time `json:"expires"`
}

// Admin is one appliance administrator.
type Admin struct {
	Name      string     `json:"name"`
	UID       int        `json:"uid"`
	Role      Role       `json:"role"`
	Created   time.Time  `json:"created"`
	CreatedBy string     `json:"createdBy"`
	Keys      []AdminKey `json:"keys"`
	Password  *Password  `json:"password,omitempty"`
	TOTP      *TOTP      `json:"totp,omitempty"`
	Invite    *Invite    `json:"invite,omitempty"`
	// LastSignIn is the last :8443 sign-in or SSH login; notices since it
	// are shown at the next one.
	LastSignIn *time.Time `json:"lastSignIn,omitempty"`
}

// HasCredentials reports whether the admin can sign in: a password and a
// TOTP secret.
func (a *Admin) HasCredentials() bool { return a.Password != nil && a.TOTP != nil }

// The lockout modes (lockout.Mode's values).
const (
	LockoutTimed         = "timed"
	LockoutUntilUnlocked = "until-unlocked"
)

// The access policy's bounds and defaults.
const (
	MinRootMinutes     = 1
	MaxRootMinutes     = 60
	MinKeyValidDays    = 1
	MaxKeyValidDays    = 1825
	DefaultKeyDays     = 365
	DefaultRootMinutes = 10
)

// Policy is the access policy (owner settings on the Access page).
type Policy struct {
	// LockoutMode is LockoutTimed or LockoutUntilUnlocked.
	LockoutMode string `json:"lockoutMode"`
	// RootCodeMinutes is how long a root-shell code works.
	RootCodeMinutes int `json:"rootCodeMinutes"`
	// RootSessionMinutes is the longest a root shell stays open.
	RootSessionMinutes int `json:"rootSessionMinutes"`
	// SSHKeyValidDays is an issued key's default validity.
	SSHKeyValidDays int `json:"sshKeyValidDays"`
}

// DefaultPolicy is the policy of a new box.
func DefaultPolicy() Policy {
	return Policy{LockoutMode: LockoutTimed, RootCodeMinutes: DefaultRootMinutes, RootSessionMinutes: DefaultRootMinutes, SSHKeyValidDays: DefaultKeyDays}
}

// Effective fills the zero fields of a store written before they existed.
func (p Policy) Effective() Policy {
	d := DefaultPolicy()
	if p.LockoutMode == "" {
		p.LockoutMode = d.LockoutMode
	}
	if p.RootCodeMinutes == 0 {
		p.RootCodeMinutes = d.RootCodeMinutes
	}
	if p.RootSessionMinutes == 0 {
		p.RootSessionMinutes = d.RootSessionMinutes
	}
	if p.SSHKeyValidDays == 0 {
		p.SSHKeyValidDays = d.SSHKeyValidDays
	}
	return p
}
