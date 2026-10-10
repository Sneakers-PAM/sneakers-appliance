// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"context"
	"strconv"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/diskguard"
)

// DiskGuard is what Status reads of the disk guard, and what CleanUpDisk
// runs.
type DiskGuard interface {
	Report() diskguard.Report
	CleanUp(ctx context.Context, actor string) diskguard.Run
}

var diskLevels = map[diskguard.Level]osadminv1.DiskLevel{
	diskguard.LevelOK:       osadminv1.DiskLevel_DISK_LEVEL_OK,
	diskguard.LevelWarning:  osadminv1.DiskLevel_DISK_LEVEL_WARNING,
	diskguard.LevelCritical: osadminv1.DiskLevel_DISK_LEVEL_CRITICAL,
}

var diskWarnings = map[string]osadminv1.WarningKind{
	diskguard.WarnSpace:        osadminv1.WarningKind_WARNING_KIND_DISK_SPACE,
	diskguard.WarnGrowth:       osadminv1.WarningKind_WARNING_KIND_DISK_GROWTH,
	diskguard.WarnWAL:          osadminv1.WarningKind_WARNING_KIND_DATA_WAL,
	diskguard.WarnAuditArchive: osadminv1.WarningKind_WARNING_KIND_AUDIT_ARCHIVE,
}

// diskStatus fills Status's volumes, data paths, last cleanup and the
// disk guard's warnings.
func (s *Server) diskStatus(out *osadminv1.GetStatusResponse) {
	if s.o.Disk == nil {
		return
	}
	r := s.o.Disk.Report()
	for _, v := range r.Volumes {
		if v.Err != "" {
			continue
		}
		pv := &osadminv1.Volume{Name: v.Name, Label: v.Label, Path: v.Path, UsedBytes: v.Used, TotalBytes: v.Used + v.Avail,
			Percent: v.Percent, Level: diskLevels[v.Level], SharedWith: v.SharedWith}
		if !v.Since.IsZero() {
			pv.LevelSince = timestamppb.New(v.Since)
		}
		out.Volumes = append(out.Volumes, pv)
	}
	for _, w := range r.Watches {
		out.DataPaths = append(out.DataPaths, &osadminv1.DataPath{Name: w.Name, Label: w.Label,
			SizeBytes: uint64(max(w.Size, 0)), GrowthBytesPerDay: w.GrowthPerDay, // #nosec G115 -- held at 0 or more
			WalBytes: uint64(max(w.WALSize, 0)), WalWarnBytes: uint64(max(w.WALWarn, 0))}) // #nosec G115 -- as above
	}
	for _, w := range r.Warnings {
		out.Warnings = append(out.Warnings, &osadminv1.Warning{Kind: diskWarnings[w.Kind], Detail: w.Detail, Critical: w.Critical})
	}
	out.LastCleanup = cleanupToWire(r.Cleanup)
}

func cleanupToWire(r *diskguard.Run) *osadminv1.DiskCleanup {
	if r == nil {
		return nil
	}
	out := &osadminv1.DiskCleanup{Time: timestamppb.New(r.At), Trigger: r.Trigger, Actor: r.Actor, FreedBytes: uint64(max(r.Freed, 0))} // #nosec G115 -- held at 0 or more
	for _, c := range r.Categories {
		out.Categories = append(out.Categories, &osadminv1.DiskCleanupCategory{Name: c.Category, FreedBytes: uint64(max(c.Freed, 0)), Note: c.Note, Error: c.Error}) // #nosec G115 -- as above
	}
	return out
}

func (h *status) CleanUpDisk(ctx context.Context, _ *connect.Request[osadminv1.CleanUpDiskRequest]) (*connect.Response[osadminv1.CleanUpDiskResponse], error) {
	s := h.s
	if s.o.Disk == nil {
		return nil, notAvailable()
	}
	c := callFrom(ctx)
	run := s.o.Disk.CleanUp(ctx, c.session.Admin)
	c.note("disk", "freed", strconv.FormatInt(run.Freed, 10))
	s.o.Logger.Info("osadmin: disk cleanup run on request", log.F("by", c.session.Admin), log.F("freed", run.Freed))
	return connect.NewResponse(&osadminv1.CleanUpDiskResponse{Cleanup: cleanupToWire(&run)}), nil
}
