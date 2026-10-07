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
	"github.com/Sneakers-PAM/sneakers-appliance/internal/setup"
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
	m, err := setup.Open(setup.BoxPaths)
	if err != nil {
		// A progress file that doesn't read could be a box set up before:
		// run nothing, and say why.
		lg.Error(err, "firstboot: the setup progress can't be read")
		u.Show(consoleui.Chrome{Version: release.Version, Phase: "firstboot"}.Page("Setup", tui.WrapStyled(tui.Alert, "The setup progress can't be read, so setup doesn't run: "+err.Error(), consoleui.Width, ""), "", ""))
		<-ctx.Done()
		return
	}
	d := wizard.Deps{
		Chrome:   consoleui.Chrome{Version: release.Version, Phase: "firstboot"},
		Custody:  b.Custody.Read,
		Network:  b.Network,
		Services: b.Services,
		Access:   b.Access,
		Setup:    b.Setup,
		Status:   b.Status.Read,
		Steps:    wizard.MachineSteps{M: m},
		Power:    b.Power,
		Enrol:    enrolment.Deps{Window: b.Window, Fetch: b.FetchKeys},
		Logger:   lg,
	}
	lg.Info("firstboot: started", log.F("version", release.Version))
	if err := wizard.Run(ctx, u, d); err != nil && ctx.Err() == nil {
		lg.Error(err, "firstboot: stopped")
		os.Exit(1)
	}
}
