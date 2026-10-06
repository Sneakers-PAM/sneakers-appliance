// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osaudit

// The power actions (spec 2, Section 2.12, point 6).
const (
	ActionReboot   = "power.reboot"
	ActionShutdown = "power.shutdown"
)

// The surfaces a power action can come from.
const (
	SurfaceConsole = "console"
	SurfaceAdmin   = "8443"
)

// PowerRequest is a reboot or shutdown someone asked for.
type PowerRequest struct {
	Action  string
	Actor   string
	KeyFP   string
	Surface string
	Source  string
	// Forced is set only after the second, explicit confirmation; the
	// default is a graceful drain.
	Forced bool
}

// Power is the audit entry for a reboot or shutdown: who, where from, and
// whether it was graceful or forced.
func Power(r PowerRequest) Entry {
	mode := "graceful"
	if r.Forced {
		mode = "forced"
	}
	return Entry{
		Actor:   r.Actor,
		KeyFP:   r.KeyFP,
		Source:  r.Source,
		Action:  r.Action,
		Outcome: "ok",
		Detail:  map[string]string{"mode": mode, "surface": r.Surface},
	}
}
