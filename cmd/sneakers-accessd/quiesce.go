// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"path/filepath"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/product"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productup"
)

// productProbe asks the installed bundle's k0s how far the product has
// come up, and brings a phased product up one phase at a time
// (docs/upgrades.md#the-phases).
func productProbe(c config) *productup.Probe {
	return &productup.Probe{
		Slot: filepath.Join(product.Dir, "current"), DataDir: "/var/lib/k0s",
		Containerd: "/run/k0s/containerd.sock", Edge: "127.0.0.1:443",
		SwitchDir: filepath.Join(c.state, "platform"), Manifests: "/var/lib/k0s/manifests",
	}
}

// quiesceBound keeps `sneakers-accessd quiesce` inside the k0s service's
// stop-timeout (2 minutes), which bounds it too.
const quiesceBound = 100 * time.Second

// quiesce is the k0s service's pre-stop: the product stops latest phase
// first, each phase's pods gone before the next, so the database stops
// last and cleanly, before k0s itself stops on every reboot, shutdown,
// update and revert.
func quiesce(ctx context.Context, c config, lg log.Logger) error {
	ctx, cancel := context.WithTimeout(ctx, quiesceBound)
	defer cancel()
	start := time.Now()
	lg.Info("accessd: stopping the product in order before k0s stops")
	if err := productProbe(c).Quiesce(ctx, time.Second); err != nil {
		return err
	}
	lg.Info("accessd: the product stopped in order", log.F("seconds", int(time.Since(start).Seconds())))
	return nil
}
