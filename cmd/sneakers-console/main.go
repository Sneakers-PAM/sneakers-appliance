// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command sneakers-console is the console in normal operation,
// information only: the status, the addresses and fingerprints, the
// warnings, and Recover access. Init runs it as the console's owner
// (services.d/console.yaml): its output reaches every console, the screen
// and the serial line alike, and what's typed on any of them reaches it.
package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/console"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/dashboard"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/switchroot"
)

func main() {
	lg := log.NewLoggerWithOptions("sneakers-console", log.WithOutput(os.Stderr), log.WithDefaultFormat(log.FormatJSON), log.WithDefaultLevel(log.LevelError))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	b := sources.Dial()
	go b.Console.Watch(ctx)
	u := newUI(lg)
	d := dashboard.Deps{
		Chrome:    consoleui.Chrome{Version: release.Version},
		Custody:   b.Custody.Read,
		Status:    b.Status.Read,
		Network:   b.Network,
		HostKeys:  func() []sources.HostKey { return sources.HostKeys(b.SSHDir) },
		Slot:      dashboard.Slot(os.Getenv(switchroot.SourceEnv)),
		Upgrades:  b.Upgrades,
		Platform:  b.Platform,
		Console:   b.Console,
		AccessNet: b.AccessNet,
		Local:     b.Local,
		Logger:    lg,
	}
	lg.Info("console: started", log.F("version", release.Version), log.F("cols", u.Cols), log.F("rows", u.Rows))
	err := dashboard.Run(ctx, u, d)
	if errors.Is(err, tui.ErrClosed) {
		// No console input (a box with no keyboard, say): keep showing the
		// status, read-only.
		lg.Warn("console: no input; the status stays on screen")
		u.Lines = nil
		err = dashboard.Run(ctx, u, d)
	}
	if err != nil && ctx.Err() == nil {
		lg.Error(err, "console: stopped")
		os.Exit(1)
	}
}

// newUI is the console on standard input and output, laid out for the
// smallest active console (the large font gives the screen 64x24), in
// colour unless the kernel command line asks for plain.
func newUI(lg log.Logger) *tui.UI {
	cmdline, _ := os.ReadFile("/proc/cmdline")
	if switched, err := console.FitFont("/dev"); err != nil {
		lg.Warn("console: the small font couldn't be set", log.F("error", err.Error()))
	} else if switched {
		lg.Info("console: the screen is too small for the large font; using " + console.SmallFont)
	}
	active, _ := os.ReadFile(console.ActivePath)
	cols, rows := console.Size("/dev", console.Names(string(active)))
	return &tui.UI{
		Screen: tui.NewScreen(os.Stdout, cols, rows, tui.ColourWanted(string(cmdline), os.Getenv("TERM"))),
		Lines:  tui.ReadLines(os.Stdin),
		Tick:   time.NewTicker(time.Second).C,
		Cols:   cols, Rows: rows,
	}
}
