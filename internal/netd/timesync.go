// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/timesync"
)

// TimeSyncs builds the SNTP engines on clk, with the clock floor kept in
// floorPath and never below build (the image's build time).
func TimeSyncs(clk timesync.Clock, floorPath string, build time.Time, lg log.Logger) func([]string, timesync.Source) TimeSync {
	sl := slog.New(SlogHandler(lg))
	if err := os.MkdirAll(filepath.Dir(floorPath), 0o700); err != nil {
		lg.Warn("netd: no directory for the clock floor", log.F("error", err.Error()))
	}
	floor, err := timesync.OpenFloor(floorPath, build)
	if err != nil {
		lg.Error(err, "netd: clock floor unreadable; starting from the build time")
	}
	return func(servers []string, src timesync.Source) TimeSync {
		e, err := timesync.New(timesync.Config{Servers: servers, Source: src, Clock: clk, Floor: floor, Logger: sl})
		if err != nil {
			lg.Error(err, "netd: time sync not started")
			e, _ = timesync.New(timesync.Config{Clock: clk, Floor: floor, Logger: sl})
		}
		return e
	}
}
