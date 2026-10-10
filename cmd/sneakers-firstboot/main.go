// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command sneakers-firstboot is first boot on the console, information
// only: the branded start-up, then the :8443 address, its certificate
// fingerprint and the one-time setup code while setup runs in a browser.
// It asks for nothing unless DHCP gives no address. Init runs it as the
// console's owner in the firstboot phase (services.d/firstboot.yaml). It
// opens :8443 and starts osadmin once the box has an address, and turns
// SSH on once the first admin exists.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"
	// The root has no zoneinfo; the box's time zone setting is read from
	// the copy linked in.
	_ "time/tzdata"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/console"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/firstboot"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/setup"
)

func main() {
	lg := log.NewLoggerWithOptions("sneakers-firstboot", log.WithOutput(os.Stderr), log.WithDefaultFormat(log.FormatJSON), log.WithDefaultLevel(log.LevelError))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	b := sources.Dial()
	go b.Console.Watch(ctx)
	cmdline, _ := os.ReadFile("/proc/cmdline")
	if switched, err := console.FitFont("/dev"); err != nil {
		lg.Warn("firstboot: the small font couldn't be set", log.F("error", err.Error()))
	} else if switched {
		lg.Info("firstboot: the screen is too small for the large font; using " + console.SmallFont)
	}
	active, _ := os.ReadFile(console.ActivePath)
	cols, rows := console.Size("/dev", console.Names(string(active)))
	u := &tui.UI{
		Screen: tui.NewScreen(os.Stdout, cols, rows, tui.ColourWanted(string(cmdline), os.Getenv("TERM"))),
		Lines:  tui.ReadLines(os.Stdin),
		Tick:   time.NewTicker(time.Second).C,
		Wake:   b.Console.Changed(),
		Cols:   cols, Rows: rows,
	}
	c := consoleui.Chrome{Version: release.Version}
	m, err := setup.Open(setup.BoxPaths)
	if err != nil {
		// A progress file that doesn't read could be a box set up before:
		// run nothing, and say why.
		lg.Error(err, "firstboot: the setup progress can't be read")
		u.Show(firstboot.ProblemPage(c, "The setup progress can't be read, so setup doesn't run: "+err.Error()))
		<-ctx.Done()
		return
	}
	d := firstboot.Deps{
		Chrome:   c,
		Custody:  b.Custody.Read,
		Network:  b.Network,
		Services: b.Services,
		Console:  b.Console,
		Setup:    b.Setup,
		Steps:    firstboot.MachineSteps{M: m},
		Power:    b.Power,
		Logger:   lg,
	}
	lg.Info("firstboot: started", log.F("version", release.Version), log.F("cols", cols), log.F("rows", rows))
	if err := firstboot.Run(ctx, u, d); err != nil && ctx.Err() == nil {
		lg.Error(err, "firstboot: stopped")
		os.Exit(1)
	}
}
