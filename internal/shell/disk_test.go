// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

// disk cleanup is offered on both origins, completes from "di", and
// calls the disk cleanup.
func TestDiskCleanup(t *testing.T) {
	for _, o := range []shell.Origin{shell.OriginSSH, shell.OriginConsole} {
		if got := shell.Complete(o, "di"); got != "disk " {
			t.Errorf("%s: Complete(di) = %q", o, got)
		}
		if got := shell.Complete(o, "disk c"); got != "disk cleanup " {
			t.Errorf("%s: Complete(disk c) = %q", o, got)
		}
		r := runShellIn(t, o, "disk cleanup", "", nil)
		if r.e != nil || strings.Join(r.b.actions(), " ") != "disk.cleanup" {
			t.Fatalf("%s: %v %v", o, r.e, r.b.actions())
		}
	}
}

func (f *fakeAccessd) CleanUpDisk(_ context.Context, r *connect.Request[accessv1.CleanUpDiskRequest]) (*connect.Response[accessv1.CleanUpDiskResponse], error) {
	f.saw(r.Header())
	return connect.NewResponse(&accessv1.CleanUpDiskResponse{Cleanup: &osadminv1.DiskCleanup{Trigger: "admin", Actor: "alice", FreedBytes: 3 << 20,
		Categories: []*osadminv1.DiskCleanupCategory{{Name: "pod-logs", FreedBytes: 3 << 20}, {Name: "wal", Note: "within the limit"}, {Name: "images", Error: "containerd timed out"}}}}), nil
}

// disk cleanup prints what each step freed, and -o json gives the same.
func TestDiskCleanupPrintsWhatItFreed(t *testing.T) {
	s, _ := withAccessd(t, &fakeAccessd{})
	out, _, err := runWith(t, s, "disk cleanup", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Freed 3.0 MiB.", "pod-logs   3.0 MiB", "wal        0 B  within the limit", "images     0 B  failed: containerd timed out"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	js, _, err := runWith(t, s, "disk cleanup -o json", "")
	if err != nil || !strings.Contains(js, `"freedBytes": 3145728`) {
		t.Fatalf("%v %s", err, js)
	}
}
