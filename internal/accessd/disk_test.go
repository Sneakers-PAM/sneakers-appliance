// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
)

// The closed shell's disk cleanup runs osadmin's CleanUpDisk as the
// login's admin, under its role and its disk.cleanup audit entry, marked
// as an SSH call.
func TestTheShellsDiskCleanupRunsAsTheAdmin(t *testing.T) {
	b := newBox(t)
	_, err := b.shell("bob").CleanUpDisk(context.Background(), connect.NewRequest(&accessv1.CleanUpDiskRequest{}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("with no disk guard: %v", err)
	}
	if e := lastEntry(t, b.log, "disk.cleanup"); e.Actor != "bob" || e.Detail["surface"] != "ssh" || e.KeyFP != b.keys["bob"].fp {
		t.Fatalf("%+v", e)
	}
}
