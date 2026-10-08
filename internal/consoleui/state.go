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

// StatePage is the branded page for s: the mark, the wordmark and the
// version, and what the box is doing.
func StatePage(c Chrome, s State) tui.Page {
	return c.BigPage([]tui.Line{
		tui.Styled(tui.Strong, "Sneakers-PAM is "+string(s)),
		tui.Text(""),
		tui.Styled(tui.Dim, stateNext[s]),
	})
}

// Render is p as a screen of cols x rows gets it: cleared and drawn in
// full, in colour when colour is set.
func Render(p tui.Page, cols, rows int, colour bool) []byte {
	var b bytes.Buffer
	_ = tui.NewScreen(&b, cols, rows, colour).Draw(p.Frame(cols, rows))
	return b.Bytes()
}
