// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/console"
)

// The persistent console log on the state volume: every line of init's and
// the services' output, across boots, rotated at keptLogMax into
// keptLogKeep older files, so it takes at most 32 MiB.
const (
	keptLogPath = "/var/lib/sneakers/log/console.log"
	keptLogMax  = 4 << 20
	keptLogKeep = 7
)

// recordSetter is the console mux (console.Taken on the box).
type recordSetter interface {
	SetRecord(console.Recorder)
}

// keptLog is the journal while the state volume is mounted.
type keptLog struct {
	to      recordSetter
	journal *console.Journal
	lg      log.Logger
}

// keepConsoleLog opens the journal at path, on the mounted state, and has
// the mux record the shared output into it, starting with what it kept
// since the boot began. A journal that can't be opened is logged and the
// box boots without one; nil is returned.
func keepConsoleLog(to recordSetter, path string, lg log.Logger) *keptLog {
	j, err := console.OpenJournal(path, keptLogMax, keptLogKeep)
	if err != nil {
		lg.Error(err, "init: the console log isn't kept on the state volume this boot", log.F("path", path))
		return nil
	}
	to.SetRecord(j)
	lg.Info("init: the console log is kept on the state volume", log.F("path", path))
	return &keptLog{to: to, journal: j, lg: lg}
}

// stop detaches the journal and closes its file. Nil-safe.
func (k *keptLog) stop() {
	if k == nil {
		return
	}
	k.to.SetRecord(nil)
	if err := k.journal.Close(); err != nil {
		k.lg.Warn("init: the console log's last lines may be missing", log.F("error", err.Error()))
	}
}

// closeLogFirst lets the journal go, then closes the volumes: an open file
// on the state volume would keep it from unmounting, and its LUKS mapping
// from closing.
func closeLogFirst(ctx context.Context, k *keptLog, closeVolumes func(context.Context) error) error {
	k.stop()
	return closeVolumes(ctx)
}
