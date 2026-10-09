// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/timesync"
)

// TimeSyncs builds the SNTP engines on clk, with the clock floor kept in
// floorPath and never below build (the image's build time). Every step of
// the clock goes to audit (clock.step), when it's set.
func TimeSyncs(clk timesync.Clock, floorPath string, build time.Time, lg log.Logger, audit osaudit.Appender) func([]string, timesync.Source) TimeSync {
	sl := slog.New(SlogHandler(lg))
	if err := os.MkdirAll(filepath.Dir(floorPath), 0o700); err != nil {
		lg.Warn("netd: no directory for the clock floor", log.F("error", err.Error()))
	}
	floor, err := timesync.OpenFloor(floorPath, build)
	if err != nil {
		lg.Error(err, "netd: clock floor unreadable; starting from the build time")
	}
	return func(servers []string, src timesync.Source) TimeSync {
		e, err := timesync.New(timesync.Config{Servers: servers, Source: src, Clock: clk, Floor: floor, Logger: sl, OnStep: stepAudit(audit, lg)})
		if err != nil {
			lg.Error(err, "netd: time sync not started")
			e, _ = timesync.New(timesync.Config{Clock: clk, Floor: floor, Logger: sl})
		}
		return e
	}
}

// stepAudit writes a clock step to the OS audit log: who (netd), the
// server and the offset.
func stepAudit(audit osaudit.Appender, lg log.Logger) func(time.Duration, string, bool) {
	if audit == nil {
		return nil
	}
	return func(offset time.Duration, server string, boot bool) {
		when := "running"
		if boot {
			when = "boot"
		}
		e := osaudit.Entry{Actor: "netd", Action: "clock.step", Target: "clock", Outcome: "ok",
			Detail: map[string]string{"server": server, "offsetMs": strconv.FormatInt(offset.Milliseconds(), 10), "at": when, "surface": "netd"}}
		if err := audit.Append(e); err != nil {
			lg.Error(err, "netd: the clock step wasn't audited")
		}
	}
}
