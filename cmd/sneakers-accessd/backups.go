// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/backupset"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/datamove"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/diskguard"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevated"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/product"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// archiveFile keeps the record of WAL the archive never got, across restarts.
const archiveFile = "backup-archive.json"

// kubectlBound bounds one kubectl; it's the longest wait a restore makes.
const kubectlBound = 6 * time.Minute

// boxBackups builds the box's backup sets, its restore and the archive's
// guard, all over the installed slot's product.yaml.
func boxBackups(c config, store *access.Store, guard *diskguard.Guard, lg log.Logger, audit *osaudit.Log) *osadmin.Backups {
	slot := filepath.Join(product.Dir, "current")
	platform := filepath.Join(c.state, "platform")
	spec := func() (productspec.Spec, error) { return productspec.Load(slot) }
	cluster := &backupset.Cluster{
		Tools: datamove.Exec{Prefix: datamove.KubePrefix(filepath.Join(slot, "k0s"), elevated.DefaultKubeconfig), Logger: lg},
		Kubectl: func(ctx context.Context, args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(ctx, kubectlBound)
			defer cancel()
			argv := append([]string{"kubectl", "--kubeconfig", elevated.DefaultKubeconfig}, args...)
			var stdout, stderr bytes.Buffer
			cmd := exec.CommandContext(ctx, filepath.Join(slot, "k0s"), argv...) // #nosec G204 -- the installed bundle's k0s, on names product.yaml declares
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				// Only stderr: a read of a Secret leaves its value on stdout.
				return nil, fmt.Errorf("kubectl %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
			}
			return stdout.Bytes(), nil
		},
	}
	note := func(action string, detail map[string]string) {
		detail["surface"] = osaudit.SurfaceAdmin
		if err := audit.Append(osaudit.Entry{Actor: "osadmin", Action: action, Target: "product", Outcome: "ok", Detail: detail}); err != nil {
			lg.Error(err, "accessd: a backup's audit entry wasn't written", log.F("action", action))
		}
	}
	restore := &backupset.Restorer{
		Spec: spec, Engine: cluster, Kube: cluster, Slot: slot,
		Journal: filepath.Join(platform, backupset.JournalFile),
		Avail: func(p string) (uint64, error) {
			u, err := diskguard.Statfs(p)
			return u.Avail, err
		},
		Audit: note, Logger: lg,
	}
	return &osadmin.Backups{
		Sets: &backupset.Manager{Spec: spec, Engine: cluster, Audit: note, Logger: lg, Recipients: func() ([]string, error) {
			var out []string
			for _, k := range store.Read().RecoveryKeys {
				out = append(out, k.PublicKey)
			}
			return out, nil
		}},
		Restore: restore,
		Guard: &backupset.Guard{
			Spec: spec, Engine: cluster, Restore: restore,
			StateFile: filepath.Join(platform, archiveFile),
			Critical:  func() bool { return dataCritical(guard) },
			Audit:     note, Logger: lg,
		},
	}
}

// dataCritical is whether the volume the database runs on is at its critical
// level.
func dataCritical(g *diskguard.Guard) bool {
	if g == nil {
		return false
	}
	for _, v := range g.Report().Volumes {
		if (v.Name == "state" || v.Name == "data") && v.Level == diskguard.LevelCritical {
			return true
		}
	}
	return false
}

// backupData is what a product reset removes of the product's backups: an
// archive left behind would stop a new install's database from starting.
func backupData(c config) []string {
	platform := filepath.Join(c.state, "platform")
	out := []string{filepath.Join(platform, backupset.JournalFile), filepath.Join(platform, archiveFile)}
	spec, err := productspec.Load(filepath.Join(product.Dir, "current"))
	if err != nil || spec.Backups == nil {
		return out
	}
	return append(out, spec.Backups.HostDir())
}

// runBackupGuard looks at the archive each minute until ctx ends.
func runBackupGuard(ctx context.Context, g *backupset.Guard) {
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
