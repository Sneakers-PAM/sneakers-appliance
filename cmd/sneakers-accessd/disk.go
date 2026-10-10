// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/diskguard"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/product"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// The box's paths the disk guard works on (docs/disk-layout.md "Keeping
// the disk from filling").
const (
	podLogDir      = "/var/lib/log"
	k0sDataDir     = "/var/lib/k0s"
	containerdSock = "/run/k0s/containerd.sock"
	k0sConfig      = "/run/sneakers/k0s/k0s.yaml"
	containerdConf = "/etc/k0s/containerd.toml"
	tmpDir         = "/tmp"
	// uploadRetention is how long a held update file nobody staged stays.
	uploadRetention = 7 * 24 * time.Hour
	tmpAge          = 7 * 24 * time.Hour
)

// diskGuard builds the disk guard: the volumes, the product's data paths
// from the installed bundle's product.yaml, and the cleanup's steps.
func diskGuard(state string, paths osadmin.Paths, audit *osaudit.Log, busy func() bool, lg log.Logger) *diskguard.Guard {
	uploads := filepath.Join(paths.APIDir(), "uploads")
	stage := filepath.Join(state, "image-stage")
	watches := func() []diskguard.Watch { return dataWatches(lg) }
	auditStep := &diskguard.AuditLog{Log: audit, Options: diskguard.ArchiveOptions(filepath.Join(state, "backup", "os-audit-archive"))}
	cleaner := &diskguard.Cleaner{
		Safety: diskguard.Safety{
			Allowed:   []string{podLogDir, uploads, stage, tmpDir},
			Protected: diskguard.BoxProtected,
		},
		Audit:     audit,
		StatePath: state,
		Logger:    lg,
		Steps: []diskguard.Step{
			diskguard.PodLogs{Dir: podLogDir},
			auditStep,
			diskguard.Images{
				K0s: filepath.Join(product.Dir, "current", "k0s"), Containerd: containerdSock,
				Slots:   []string{filepath.Join(product.Dir, "a"), filepath.Join(product.Dir, "b")},
				Pinned:  []string{k0sConfig, containerdConf},
				Measure: func() (diskguard.Usage, error) { return diskguard.Statfs(k0sDataDir) },
			},
			diskguard.Updates{Uploads: uploads, StageDir: stage, Retention: uploadRetention, Busy: busy},
			diskguard.Tmp{Dir: tmpDir, Age: tmpAge},
			diskguard.WAL{Watches: watches},
		},
	}
	return &diskguard.Guard{
		Volumes: []diskguard.Volume{
			{Name: "state", Label: "State", Path: state},
			{Name: "data", Label: "Product data", Path: productspec.DataRoot},
			{Name: "backup", Label: "Backup", Path: filepath.Join(state, "backup")},
		},
		Watches:   watches,
		Cleaner:   cleaner,
		Archive:   auditStep.Archive,
		Audit:     audit,
		StateFile: filepath.Join(paths.APIDir(), "disk-guard.json"),
		Logger:    lg,
	}
}

// dataWatches are the installed product's data paths: the ones its
// product.yaml declares, else every directory under the data root.
func dataWatches(lg log.Logger) []diskguard.Watch {
	spec, err := productspec.Load(filepath.Join(product.Dir, "current"))
	if err != nil {
		lg.Warn("accessd: the installed product.yaml doesn't read; watching every data directory", log.F("error", err.Error()))
	}
	var out []diskguard.Watch
	for _, d := range spec.Data {
		out = append(out, diskguard.Watch{Name: d.Name, Label: d.Label, Path: d.HostPath(), WAL: d.WAL, WALWarn: d.WALWarnBytes()})
	}
	if len(out) > 0 {
		return out
	}
	ents, _ := os.ReadDir(productspec.DataRoot)
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, diskguard.Watch{Name: e.Name(), Label: e.Name(), Path: filepath.Join(productspec.DataRoot, e.Name())})
		}
	}
	return out
}

// runDiskGuard ticks the guard each minute until ctx ends, on its own, so
// a long cleanup never holds up accessd's other minute work.
func runDiskGuard(ctx context.Context, g *diskguard.Guard) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		g.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
