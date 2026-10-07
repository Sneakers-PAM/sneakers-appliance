// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package consoleui is the appliance console: the first-boot wizard and
// the normal-phase dashboard (in its wizard and dashboard packages), the
// texts in screens, the renderer in tui and the backends in sources. This
// file is what every page shares: the header, the reduced-protection
// banner and the footer with the version, the phase and the clock.
package consoleui

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
)

// Width is the text width pages are laid out for: an 80-column console,
// less the margin and the last column.
const Width = 77

// NTP states for the footer.
const (
	NTPSynced   = "synced"
	NTPUnsynced = "not synced"
	NTPUnknown  = "unknown"
)

// Chrome is what every page shows around its body.
type Chrome struct {
	Version string
	Phase   string
	Host    string
	NTP     string
	Now     func() time.Time
	// Protection and Mode are init's; Known is false until init answered.
	Protection keycustody.Protection
	Mode       keycustody.Mode
	Known      bool
}

// Page puts body into the shared frame.
func (c Chrome) Page(title string, body []tui.Line, keys, prompt string) tui.Page {
	return tui.Page{
		Title:  "Sneakers-PAM appliance  " + title,
		Right:  c.Host,
		Banner: c.Banner(),
		Body:   body,
		Keys:   keys,
		Prompt: prompt,
		Footer: c.Footer(),
	}
}

// Banner is the reduced-protection banner: the level and its reason in
// alert, then in short how to raise it. Empty at full protection.
func (c Chrome) Banner() []tui.Line {
	if !c.Known || c.Protection.Level != keycustody.LevelReduced {
		return nil
	}
	out := tui.WrapStyled(tui.Alert, screens.ProtectionText(c.Protection, c.Mode), Width-3, "")
	for i := range out {
		lead := "   "
		if i == 0 {
			lead = "!! "
		}
		out[i] = append(tui.Line{{Text: lead, Style: tui.Alert}}, out[i]...)
	}
	if s := RaiseShort(c.Protection); s != "" {
		out = append(out, tui.Line{{Text: "   "}, {Text: s, Style: tui.Warn}})
	}
	return out
}

// RaiseShort is RaiseText in one line, for the banner.
func RaiseShort(p keycustody.Protection) string {
	switch p.Reason {
	case keycustody.ReasonSecureBootOff:
		return "Raise it later on the :8443 Status page (Secure Boot on); no reinstall."
	case keycustody.ReasonNoSecureBootFirmware:
		return "Only firmware with Secure Boot can raise it, from the :8443 Status page."
	case keycustody.ReasonNoTPM:
		return "Fixed until a reinstall on hardware with a TPM (or a VM with a vTPM)."
	}
	return ""
}

// Footer is the version, the phase, the time (UTC) and its NTP state.
func (c Chrome) Footer() string {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	ntp := c.NTP
	if ntp == "" {
		ntp = NTPUnknown
	}
	return fmt.Sprintf("Sneakers-PAM %s | %s | %s UTC | NTP %s", c.Version, c.Phase, now().UTC().Format("2006-01-02 15:04"), ntp)
}

// FingerprintLines splits a colon-hex SHA-256 fingerprint into two lines
// of 16 bytes, so it fits 80 columns in full.
func FingerprintLines(fp string) []string {
	parts := strings.Split(fp, ":")
	if len(parts) <= 16 {
		return []string{fp}
	}
	return []string{strings.Join(parts[:16], ":"), strings.Join(parts[16:], ":")}
}

// Field is a label and its value, the label padded to width.
func Field(label string, width int, value ...tui.Span) tui.Line {
	return append(tui.Line{{Text: fmt.Sprintf("%-*s", width, label)}}, value...)
}

// Steps is the first-boot step strip: done steps ticked, the current one
// bold.
func Steps(current int, done []bool) tui.Line {
	names := []string{"Network", "Protection", "Admin", "Recovery", "Sign-in"}
	var l tui.Line
	for i, n := range names {
		mark, st := "[ ]", tui.Normal
		switch {
		case i < len(done) && done[i]:
			mark, st = "[x]", tui.OK
		case i+1 == current:
			mark, st = "[>]", tui.Bold
		}
		if i > 0 {
			l = append(l, tui.Span{Text: "  "})
		}
		l = append(l, tui.Span{Text: fmt.Sprintf("%s %d %s", mark, i+1, n), Style: st})
	}
	return l
}

// Describe is an error as one sentence for the screen: a Connect error's
// message without its code prefix.
func Describe(err error) string {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Message()
	}
	return err.Error()
}
