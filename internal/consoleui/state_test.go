// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package consoleui_test

import (
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui/tuitest"
)

// While the box starts, reboots or shuts down, the screen shows one
// branded page for the state and nothing else.
func TestStatePages(t *testing.T) {
	c := consoleui.Chrome{Version: "0.1.0"}
	for name, st := range map[string]consoleui.State{"state-starting": consoleui.Starting, "state-rebooting": consoleui.Rebooting, "state-shutting-down": consoleui.ShuttingDown} {
		p := consoleui.StatePage(c, st)
		if !p.Big || p.Prompt != "" || len(p.Keys) != 0 {
			t.Fatalf("%s: %+v", name, p)
		}
		tuitest.Golden(t, name, p)
	}
	for st, want := range map[consoleui.State]string{consoleui.Starting: "Sneakers-PAM is starting", consoleui.Rebooting: "Sneakers-PAM is rebooting", consoleui.ShuttingDown: "Sneakers-PAM is shutting down"} {
		if text := consoleui.StatePage(c, st).Frame(64, 24).Text(); !strings.Contains(text, want) {
			t.Errorf("the %s page lacks %q:\n%s", st, want, text)
		}
	}
}

// Render is the page as the screen gets it: cleared, drawn in full, and
// with the cursor hidden.
func TestRenderDrawsTheWholePage(t *testing.T) {
	b := string(consoleui.Render(consoleui.StatePage(consoleui.Chrome{Version: "0.1.0"}, consoleui.Rebooting), 64, 24, true))
	for _, want := range []string{"\x1b[H\x1b[2J", "Sneakers-PAM is rebooting", "\x1b[?25l", "\x1b[34m"} {
		if !strings.Contains(b, want) {
			t.Errorf("the rendered page lacks %q: %q", want, b)
		}
	}
	if plain := string(consoleui.Render(consoleui.StatePage(consoleui.Chrome{}, consoleui.Starting), 80, 24, false)); strings.Contains(plain, "\x1b[34m") {
		t.Errorf("the plain page has colour: %q", plain)
	}
}
