// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package consoleui is the appliance console: the first-boot info screens
// and the normal-phase dashboard (in its firstboot and dashboard
// packages), the texts in screens, the renderer in tui and the backends in
// sources. This file is what every page shares: the wordmark, the
// protection and clock lines, and the fingerprints in groups of four.
package consoleui

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
)

// Width is the text width pages are laid out for: the body block that
// fits the large font's 64 columns.
const Width = tui.Width

// Name is the wordmark.
const Name = "Sneakers-PAM Appliance"

// NTP states.
const (
	NTPSynced   = "synced"
	NTPUnsynced = "not synced"
	NTPUnknown  = "unknown"
)

// Chrome is what every page shows around its body.
type Chrome struct {
	Version string
	// Info is the one-row header's right side (the slot and the nodes).
	Info string
	Host string
	NTP  string
	Now  func() time.Time
	// Protection and Mode are init's; Known is false until init answered.
	Protection keycustody.Protection
	Mode       keycustody.Mode
	Known      bool
}

// Page puts body under the one-row header.
func (c Chrome) Page(body []tui.Line, keys tui.Line, prompt string) tui.Page {
	return tui.Page{Name: Name, Version: c.Version, Info: c.Info, Body: body, Keys: keys, Prompt: prompt}
}

// BigPage puts body under the mark and the wordmark: the boot and info
// screens.
func (c Chrome) BigPage(body []tui.Line) tui.Page {
	return tui.Page{Big: true, Name: Name, Version: c.Version, Body: body}
}

// Key is one key and what it does, for a page's keys row.
func Key(key, what string) tui.Line {
	return tui.Line{{Text: key + "  " + what, Style: tui.Dim}}
}

// Keys joins key lines with a gap.
func Keys(ks ...tui.Line) tui.Line {
	var out tui.Line
	for i, k := range ks {
		if i > 0 {
			out = append(out, tui.Span{Text: "     ", Style: tui.Dim})
		}
		out = append(out, k...)
	}
	return out
}

// StatusLine is a label padded to width, a status word in its colour
// padded so the details line up, and the details, dim.
func StatusLine(label string, width int, word string, st tui.Style, detail string) tui.Line {
	return tui.Line{{Text: fmt.Sprintf("%-*s", width, label)}, {Text: word, Style: st}, {Text: strings.Repeat(" ", max(8-len(word), 1)) + detail, Style: tui.Dim}}
}

// ProtectionLine is the protection with its label padded to width: the
// level in its status colour, then in plain words what it rests on.
func (c Chrome) ProtectionLine(width int) tui.Line {
	l := c.ProtectionStatus(width)
	// The details follow the level after two blanks, without a status
	// column to line up with.
	l[2].Text = "  " + strings.TrimLeft(l[2].Text, " ")
	return l
}

// ProtectionStatus is ProtectionLine with its details in the status
// column, as the dashboard lines them up.
func (c Chrome) ProtectionStatus(width int) tui.Line {
	if !c.Known {
		return StatusLine("Protection", width, "UNKNOWN", tui.Warn, "the boot hasn't answered yet")
	}
	if c.Protection.Level == keycustody.LevelReduced {
		return StatusLine("Protection", width, "REDUCED", tui.Warn, ProtectionReason(c.Protection, c.Mode))
	}
	return StatusLine("Protection", width, "FULL", tui.OK, ProtectionReason(c.Protection, c.Mode))
}

// ProtectionReason is what the protection rests on, in plain words.
func ProtectionReason(p keycustody.Protection, m keycustody.Mode) string {
	sb := "Secure Boot on"
	switch p.Reason {
	case keycustody.ReasonSecureBootOff:
		sb = "Secure Boot off"
	case keycustody.ReasonNoSecureBootFirmware:
		sb = "no Secure Boot"
	}
	if m == keycustody.ModeKeyfile {
		return "no TPM, " + sb
	}
	return sb + ", key in the TPM"
}

// ClockLine is the clock's state with its label padded to width.
func (c Chrome) ClockLine(width int) tui.Line {
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	t := now().Format("15:04 MST")
	switch c.NTP {
	case NTPSynced:
		return StatusLine("Clock", width, "OK", tui.OK, "synced "+t)
	case NTPUnsynced:
		return StatusLine("Clock", width, "UNSYNCED", tui.Warn, t+" by the box's own clock")
	}
	return StatusLine("Clock", width, "UNKNOWN", tui.Dim, t)
}

// FingerprintGroups writes a colon-hex SHA-256 fingerprint as groups of
// four hex digits, eight groups to a line, so it can be read aloud.
func FingerprintGroups(fp string) []string {
	hex := strings.ToUpper(strings.ReplaceAll(fp, ":", ""))
	if hex == "" {
		return nil
	}
	var groups []string
	for len(hex) > 4 {
		groups = append(groups, hex[:4])
		hex = hex[4:]
	}
	groups = append(groups, hex)
	var out []string
	for len(groups) > 8 {
		out = append(out, strings.Join(groups[:8], " "))
		groups = groups[8:]
	}
	return append(out, strings.Join(groups, " "))
}

// SSHFingerprintGroups writes an OpenSSH SHA256: fingerprint in groups of
// four, six groups on the first line.
func SSHFingerprintGroups(fp string) []string {
	const prefix = "SHA256:"
	body := strings.TrimPrefix(fp, prefix)
	var groups []string
	for len(body) > 4 {
		groups = append(groups, body[:4])
		body = body[4:]
	}
	if body != "" {
		groups = append(groups, body)
	}
	if len(groups) <= 6 {
		return []string{prefix + strings.Join(groups, " ")}
	}
	return []string{prefix + strings.Join(groups[:6], " "), strings.Repeat(" ", len(prefix)) + strings.Join(groups[6:], " ")}
}

// Expires says how long a code has left, in whole minutes.
func Expires(left time.Duration) string {
	switch {
	case left <= 0:
		return "expired, a new one is on its way"
	case left < time.Minute:
		return "expires in under a minute"
	}
	// Whole minutes left, not counting the one running: a fresh 60-minute
	// code says 59.
	return fmt.Sprintf("expires in %d min", int((left - time.Nanosecond).Minutes()))
}

// Field is a label and its value, the label padded to width.
func Field(label string, width int, value ...tui.Span) tui.Line {
	return append(tui.Line{{Text: fmt.Sprintf("%-*s", width, label)}}, value...)
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
