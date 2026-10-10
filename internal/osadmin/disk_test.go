// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/diskguard"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

type fakeDisk struct {
	report diskguard.Report
	asked  []string
}

func (f *fakeDisk) Report() diskguard.Report { return f.report }
func (f *fakeDisk) CleanUp(_ context.Context, actor string) diskguard.Run {
	f.asked = append(f.asked, actor)
	return diskguard.Run{At: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC), Trigger: diskguard.TriggerAdmin, Actor: actor, Freed: 4096,
		Categories: []diskguard.CategoryResult{{Category: diskguard.CategoryPodLogs, Freed: 4096}, {Category: diskguard.CategoryWAL, Note: "within the limit"}}}
}

// Status shows each volume with its level, the product's data paths and
// the disk guard's warnings, a critical one marked.
func TestStatusShowsTheVolumesAndTheirAlerts(t *testing.T) {
	fd := &fakeDisk{report: diskguard.Report{
		Volumes: []diskguard.VolumeReport{
			{Volume: diskguard.Volume{Name: "state", Label: "State", Path: "/var/lib"}, Used: 92, Avail: 8, Percent: 92, Level: diskguard.LevelCritical, Since: time.Date(2026, 10, 9, 11, 0, 0, 0, time.UTC)},
			{Volume: diskguard.Volume{Name: "data", Label: "Product data", Path: "/var/lib/sneakers-data"}, Used: 92, Avail: 8, Percent: 92, SharedWith: "state"},
		},
		Watches:  []diskguard.WatchReport{{Watch: diskguard.Watch{Name: "database", Label: "The database", WALWarn: 1 << 30}, Size: 1 << 30, GrowthPerDay: 1 << 20, WALSize: 1 << 28}},
		Warnings: []diskguard.Warning{{Kind: diskguard.WarnSpace, Critical: true, Detail: "The state volume is 92% full."}},
	}}
	b := newBox(t, false, func(_ *box, o *osadmin.Options) { o.Disk = fd })
	alice := b.browser()
	alice.signIn("alice")
	st, err := osadminv1connect.NewStatusServiceClient(alice.hc, b.ts.URL).GetStatus(context.Background(), connect.NewRequest(&osadminv1.GetStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	vs := st.Msg.GetVolumes()
	if len(vs) != 2 || vs[0].GetLevel() != osadminv1.DiskLevel_DISK_LEVEL_CRITICAL || vs[0].GetTotalBytes() != 100 || vs[1].GetSharedWith() != "state" || vs[0].GetLevelSince() == nil {
		t.Fatalf("volumes %v", vs)
	}
	if dp := st.Msg.GetDataPaths(); len(dp) != 1 || dp[0].GetWalWarnBytes() != 1<<30 || dp[0].GetGrowthBytesPerDay() != 1<<20 {
		t.Fatalf("data paths %v", dp)
	}
	var found bool
	for _, w := range st.Msg.GetWarnings() {
		if w.GetKind() == osadminv1.WarningKind_WARNING_KIND_DISK_SPACE && w.GetCritical() {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings %v", st.Msg.GetWarnings())
	}
}

// Clean up now asks for a fresh code, runs the cleanup as the admin and is
// audited.
func TestCleanUpDiskNeedsAStepUp(t *testing.T) {
	fd := &fakeDisk{}
	b := newBox(t, false, func(_ *box, o *osadmin.Options) { o.Disk = fd })
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	sc := osadminv1connect.NewStatusServiceClient(alice.hc, b.ts.URL)
	b.clk.Advance(6 * time.Minute)
	_, err := sc.CleanUpDisk(ctx, connect.NewRequest(&osadminv1.CleanUpDiskRequest{}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_STEPUP_REQUIRED")
	if len(fd.asked) != 0 {
		t.Fatal("a cleanup ran without the step-up")
	}
	alice.stepUp("alice")
	out, err := sc.CleanUpDisk(ctx, connect.NewRequest(&osadminv1.CleanUpDiskRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	c := out.Msg.GetCleanup()
	if c.GetFreedBytes() != 4096 || c.GetActor() != "alice" || len(c.GetCategories()) != 2 || c.GetCategories()[1].GetNote() != "within the limit" {
		t.Fatalf("%v", c)
	}
	if e := lastEntry(t, b.log, "disk.cleanup"); e.Outcome != "ok" || e.Actor != "alice" || e.Detail["freed"] != "4096" || e.Target != "disk" {
		t.Fatalf("audit %+v", e)
	}
}

// With no disk guard wired, Clean up now isn't available.
func TestCleanUpDiskWithoutAGuard(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	_, err := osadminv1connect.NewStatusServiceClient(alice.hc, b.ts.URL).CleanUpDisk(context.Background(), connect.NewRequest(&osadminv1.CleanUpDiskRequest{}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("%v", err)
	}
}
