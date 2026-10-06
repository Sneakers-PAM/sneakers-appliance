// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osaudit_test

import (
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

func TestPowerEntryRecordsGracefulByDefault(t *testing.T) {
	l := openLog(t)
	mustNoErr(t, l.Append(osaudit.Power(osaudit.PowerRequest{
		Action: osaudit.ActionReboot, Actor: "alice", KeyFP: "SHA256:abc",
		Surface: osaudit.SurfaceAdmin, Source: "192.0.2.10",
	})))
	es, err := l.Entries()
	mustNoErr(t, err)
	e := es[0]
	if e.Action != "power.reboot" || e.Actor != "alice" || e.Source != "192.0.2.10" || e.KeyFP != "SHA256:abc" {
		t.Fatalf("entry = %+v", e)
	}
	if e.Detail["mode"] != "graceful" || e.Detail["surface"] != "8443" {
		t.Fatalf("detail = %v, want a graceful 8443 entry", e.Detail)
	}
}

func TestPowerEntryRecordsTheForcedFlag(t *testing.T) {
	l := openLog(t)
	mustNoErr(t, l.Append(osaudit.Power(osaudit.PowerRequest{
		Action: osaudit.ActionShutdown, Actor: "console", Surface: osaudit.SurfaceConsole, Forced: true,
	})))
	es, err := l.Entries()
	mustNoErr(t, err)
	e := es[0]
	if e.Action != "power.shutdown" || e.Detail["mode"] != "forced" || e.Detail["surface"] != "console" {
		t.Fatalf("entry = %+v, want a forced console shutdown", e)
	}
}
