// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"io"
	"os"
	"sync"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/console"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
)

// printkPath holds the kernel's console loglevels.
const printkPath = "/proc/sys/kernel/printk"

// quietKernel keeps the kernel's messages off the consoles but its
// emergencies (console loglevel 1), as loglevel=1 on the command line
// does; they stay in the kernel log.
func quietKernel(path string) error {
	return os.WriteFile(path, []byte("1 4 1 7\n"), 0o600)
}

// bootScreen is what the screen shows while no console program owns it:
// the branded page for the box's state, in place of the kernel's, init's
// and the services' lines, which go to the serial line and the console
// log. init's own screens, which ask on the console, turn it loud.
type bootScreen struct {
	con        *console.Taken
	cols, rows int
	colour     bool
}

func newBootScreen(con *console.Taken) bootScreen {
	b := bootScreen{con: con, cols: 64, rows: 24}
	if con == nil {
		return b
	}
	cmdline, _ := os.ReadFile("/proc/cmdline")
	b.cols, b.rows = console.Size("/dev", con.Kept)
	b.colour = tui.ColourWanted(string(cmdline), os.Getenv("TERM"))
	return b
}

func (b bootScreen) page(s consoleui.State) []byte {
	return consoleui.Render(consoleui.StatePage(consoleui.Chrome{Version: release.Version}, s), b.cols, b.rows, b.colour)
}

// starting shows "Sneakers-PAM is starting" and keeps the lines off the
// screen.
func (b bootScreen) starting() { b.con.Quiet(b.page(consoleui.Starting)) }

// loud clears the screen for one of init's own screens.
func (b bootScreen) loud() { b.con.Loud() }

// stopping shows the rebooting or shutting down page until the power goes.
func (b bootScreen) stopping(action string) {
	s := consoleui.Rebooting
	if action == osaudit.ActionShutdown {
		s = consoleui.ShuttingDown
	}
	b.con.Hold(b.page(s))
}

// asking is the writer for init's own screens: it turns the screens loud
// before its first write.
type asking struct {
	w    io.Writer
	loud func()
	once sync.Once
}

func (a *asking) Write(p []byte) (int, error) {
	a.once.Do(a.loud)
	return a.w.Write(p)
}
