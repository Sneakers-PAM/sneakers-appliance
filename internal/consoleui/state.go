// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package consoleui

import (
	"bytes"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
)

// State is what the box is doing while no console program shows anything:
// init puts its page on the screen in place of the kernel's and the
// services' lines.
type State string

// The states init shows.
const (
	Starting     State = "starting"
	Rebooting    State = "rebooting"
	ShuttingDown State = "shutting down"
)

var stateNext = map[State]string{
	Starting:     "Leave it running.",
	Rebooting:    "Leave it powered on; it comes back by itself.",
	ShuttingDown: "It powers off by itself.",
}

// stateTakes is how long the box can take to come back, for the states
// that end in it going away.
var stateTakes = map[State]string{
	Rebooting:    "It can take more than 5 minutes to come back.",
	ShuttingDown: "Starting it again can take more than 5 minutes.",
}

// StatePage is the branded page for s: the mark, the wordmark and the
// version, and what the box is doing.
func StatePage(c Chrome, s State) tui.Page {
	lines := []tui.Line{
		tui.Styled(tui.Strong, "Sneakers-PAM is "+string(s)),
		tui.Text(""),
		tui.Styled(tui.Dim, stateNext[s]),
	}
	if t := stateTakes[s]; t != "" {
		lines = append(lines, tui.Styled(tui.Dim, t))
	}
	return c.BigPage(lines)
}

// Render is p as a screen of cols x rows gets it: cleared and drawn in
// full, in colour when colour is set.
func Render(p tui.Page, cols, rows int, colour bool) []byte {
	var b bytes.Buffer
	_ = tui.NewScreen(&b, cols, rows, colour).Draw(p.Frame(cols, rows))
	return b.Bytes()
}
