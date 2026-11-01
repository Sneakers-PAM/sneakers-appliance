// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/datamove"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/diskguard"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevated"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/product"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

// followingProbe is the probe of the one process that follows the product:
// it can run the data move a slot declares (docs/data-move.md). k0s's
// pre-stop and the product reset ask the plain one.
func followingProbe(c config, lg log.Logger, audit *osaudit.Log) *productup.Probe {
	p := productProbe(c)
	p.Move = dataMover(c, lg, audit)
	return p
}

func moveDumps() string { return filepath.Join(keycustody.BackupTarget, "data-move") }

func dataMover(c config, lg log.Logger, audit *osaudit.Log) *datamove.Runner {
	slot := filepath.Join(product.Dir, "current")
	return &datamove.Runner{
		Logger: lg,
		New: func(spec productspec.DataMove, svc datamove.Services, progress func(string)) *datamove.Move {
			return &datamove.Move{
				Spec: spec, Slot: slot,
				BackupDir: moveDumps(),
				Journal:   filepath.Join(c.state, "platform", datamove.JournalFile),
				Volumes:   productspec.DataRoot,
				Engine: &datamove.PG{Logger: lg, Shell: datamove.Exec{
					Prefix: datamove.KubePrefix(filepath.Join(slot, "k0s"), elevated.DefaultKubeconfig), Logger: lg,
				}},
				Services: svc, Disk: diskUsage, Progress: progress, Logger: lg,
				Audit: func(action string, detail map[string]string) {
					detail["surface"] = osaudit.SurfaceAdmin
					if err := audit.Append(osaudit.Entry{Actor: "osadmin", Action: action, Target: "product", Outcome: "ok", Detail: detail}); err != nil {
						lg.Error(err, "accessd: a data move's audit entry wasn't written", log.F("action", action))
					}
				},
			}
		},
	}
}

func diskUsage(p string) (datamove.Usage, error) {
	u, err := diskguard.Statfs(p)
	return datamove.Usage{Avail: u.Avail, Device: u.Device}, err
}
