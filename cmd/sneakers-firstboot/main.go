// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command sneakers-firstboot is first boot on the console: the network,
// the protection chosen at boot, the first admin and the SSH key
// enrolment, then :8443 for the recovery keys and the first sign-in. Init
// runs it as the console's owner in the firstboot phase
// (services.d/firstboot.yaml). It starts sshd when the admin step starts
// and :8443 once that step is done.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/enrolment"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/wizard"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
)

func main() {
	lg := log.NewLoggerWithOptions("sneakers-firstboot", log.WithOutput(os.Stderr), log.WithDefaultFormat(log.FormatJSON), log.WithDefaultLevel(log.LevelError))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	b := sources.Dial()
	cmdline, _ := os.ReadFile("/proc/cmdline")
	u := &tui.UI{
		Screen: tui.NewScreen(os.Stdout, 80, 24, tui.ColourWanted(string(cmdline), os.Getenv("TERM"))),
		Lines:  tui.ReadLines(os.Stdin),
		Tick:   time.NewTicker(time.Second).C,
		Cols:   80, Rows: 24,
	}
	d := wizard.Deps{
		Chrome:   consoleui.Chrome{Version: release.Version, Phase: "firstboot"},
		Custody:  b.Custody.Read,
		Network:  b.Network,
		Services: b.Services,
		Access:   b.Access,
		Setup:    b.Setup,
		Status:   b.Status.Read,
		// The first-boot step machine replaces this when it's in the build.
		Steps:  &wizard.DerivedSteps{Access: b.Access, Setup: b.Setup},
		Power:  b.Power,
		Enrol:  enrolment.Deps{Window: b.Window, Fetch: b.FetchKeys},
		Logger: lg,
	}
	lg.Info("firstboot: started", log.F("version", release.Version))
	if err := wizard.Run(ctx, u, d); err != nil && ctx.Err() == nil {
		lg.Error(err, "firstboot: stopped")
		os.Exit(1)
	}
}
