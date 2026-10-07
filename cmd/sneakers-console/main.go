// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command sneakers-console is the console in normal operation: the status
// view, the menu of console commands, Recover access and the recent
// messages. Init runs it as the console's owner (services.d/console.yaml):
// its output reaches every console, the screen and the serial line alike,
// and what's typed on any of them reaches it.
package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/dashboard"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/enrolment"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/switchroot"
)

// messagesFile is where init puts the shared output while this program
// owns the consoles.
const messagesFile = "/run/sneakers/console.log"

func main() {
	lg := log.NewLoggerWithOptions("sneakers-console", log.WithOutput(os.Stderr), log.WithDefaultFormat(log.FormatJSON), log.WithDefaultLevel(log.LevelError))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	b := sources.Dial()
	u := newUI()
	d := dashboard.Deps{
		Chrome:   consoleui.Chrome{Version: release.Version, Phase: "normal"},
		Custody:  b.Custody.Read,
		Status:   b.Status.Read,
		Network:  b.Network,
		HostKeys: func() []sources.HostKey { return sources.HostKeys(b.SSHDir) },
		Slot:     dashboard.Slot(os.Getenv(switchroot.SourceEnv)),
		Upgrades: b.Upgrades,
		Platform: b.Platform,
		Shell:    b.Shell,
		Access:   b.Access,
		Local:    b.Local,
		Enrol: enrolment.Deps{
			Window: b.Window, Fetch: b.FetchKeys,
			Addresses: func(ctx context.Context) ([]string, error) { a, err := b.Network.Status(ctx); return a.Management, err },
			SSH: func(ctx context.Context) error {
				up, err := b.Services.Running(ctx, "sshd")
				if err == nil && !up {
					err = errors.New("the SSH service isn't running")
				}
				return err
			},
		},
		MessagesFile: messagesFile,
		Logger:       lg,
	}
	lg.Info("console: started", log.F("version", release.Version))
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

// newUI is the console on standard input and output: 80x24, the size
// every console the box has can show, in colour unless the kernel command
// line asks for plain.
func newUI() *tui.UI {
	cmdline, _ := os.ReadFile("/proc/cmdline")
	color := tui.ColourWanted(string(cmdline), os.Getenv("TERM"))
	return &tui.UI{
		Screen: tui.NewScreen(os.Stdout, 80, 24, color),
		Lines:  tui.ReadLines(os.Stdin),
		Tick:   time.NewTicker(time.Second).C,
		Cols:   80, Rows: 24,
	}
}
