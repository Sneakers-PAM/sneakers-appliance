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

// The two roles (spec 2, Section 2.6).
const (
	// RoleOwner can do everything, including managing admins and approving
	// elevations.
	RoleOwner Role = "owner"
	// RoleAdmin can do everything except managing other admins and approving
	// elevations.
	RoleAdmin Role = "admin"
)

// How a key reached the store.
const (
	ViaEnrol           = "enrol"
	ViaShell           = "shell"
	ViaOSAdmin         = "osadmin"
	ViaURL             = "url"
	ViaTyped           = "typed"
	ViaConsoleRecovery = "console-recovery"
)

// FirstUID is the uid of the first admin; uids count up from it and are
// never reused.
const FirstUID = 20000

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,30}$`)

// ReservedNames are the system accounts an admin can't be named after.
// console is the OS audit log's actor name for the console; an admin by that
// name would make audit entries ambiguous.
var ReservedNames = []string{"root", "maint", "enrol", "sshd", "sshkeys", "nobody", "osadmin", "console"}

// ValidName reports whether name may be an admin's name.
func ValidName(name string) bool {
	return namePattern.MatchString(name) && !slices.Contains(ReservedNames, name)
}

// AdminKey is one of an admin's login keys.
type AdminKey struct {
	Key
	Added    time.Time  `json:"added"`
	AddedBy  string     `json:"addedBy"`
	Via      string     `json:"via"`
	LastUsed *time.Time `json:"lastUsed,omitempty"`
}

// Admin is one appliance administrator.
type Admin struct {
	Name      string     `json:"name"`
	UID       int        `json:"uid"`
	Role      Role       `json:"role"`
	Created   time.Time  `json:"created"`
	CreatedBy string     `json:"createdBy"`
	Keys      []AdminKey `json:"keys"`
	// ApprovalHoldUntil is set when a key was added through the console's
	// Recover access: until then the admin can't approve elevations.
	ApprovalHoldUntil *time.Time `json:"approvalHoldUntil"`
}

// Policy is the elevation policy.
type Policy struct {
	MaxMinutes                  int  `json:"maxMinutes"`
	DefaultMinutes              int  `json:"defaultMinutes"`
	SelfApprovalWhenSingleOwner bool `json:"selfApprovalWhenSingleOwner"`
}

// DefaultPolicy is the policy of a new box.
func DefaultPolicy() Policy {
	return Policy{MaxMinutes: 240, DefaultMinutes: 60, SelfApprovalWhenSingleOwner: true}
}
