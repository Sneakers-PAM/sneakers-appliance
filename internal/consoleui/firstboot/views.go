// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package firstboot is first boot on the console, information only: the
// branded start-up, then the address to open, the certificate to check and
// the one-time setup code, while setup runs on the :8443 page. The only
// input is the network editor, shown when DHCP gives no address.
package firstboot

import (
	"fmt"
	"strings"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
)

const width = consoleui.Width

// Item is one start-up step and how far it is.
type Item struct {
	Name string
	// State is "ok", "busy" or "" (not started).
	State string
	// Took is how long a busy step has run.
	Took time.Duration
}

// StartingPage is the branded start-up: the steps done and the one
// running.
func StartingPage(c consoleui.Chrome, items []Item) tui.Page {
	b := []tui.Line{tui.Text("Starting up. Leave it running."), tui.Text("")}
	for _, it := range items {
		mark, st := "[  ]", tui.Dim
		switch it.State {
		case "ok":
			mark, st = "[ok]", tui.OK
		case "busy":
			mark, st = "[..]", tui.Warn
		}
		l := tui.Line{{Text: "   "}, {Text: mark, Style: st}, {Text: "  " + it.Name}}
		if it.State == "busy" && it.Took > 0 {
			l = append(l, tui.Span{Text: fmt.Sprintf("   %d:%02d", int(it.Took.Minutes()), int(it.Took.Seconds())%60), Style: tui.Dim})
		}
		b = append(b, l)
	}
	return c.BigPage(b)
}

// InfoPage is the main first-boot screen: open this address, check this
// certificate, type this code.
func InfoPage(c consoleui.Chrome, info sources.ConsoleInfo, now time.Time, errLine string) tui.Page {
	b := []tui.Line{tui.Styled(tui.Strong, "Open this address in your browser:")}
	urls := info.URLs
	if len(urls) == 0 && info.URL != "" {
		urls = []string{info.URL}
	}
	if len(urls) > 2 {
		urls = urls[:2]
	}
	if len(urls) == 0 {
		b = append(b, tui.Styled(tui.Warn, "   waiting for an address"))
	}
	for _, u := range urls {
		b = append(b, tui.Styled(tui.Strong, "   "+u))
	}
	if info.FQDN != "" && len(urls) > 0 {
		b = append(b, tui.Styled(tui.Strong, "   https://"+info.FQDN+":8443"))
	}
	b = append(b, tui.Text(""), tui.Styled(tui.Dim, "Certificate fingerprint"))
	fp := consoleui.FingerprintGroups(info.CertFingerprint)
	if len(fp) == 0 {
		b = append(b, tui.Styled(tui.Dim, "   shown once the setup page is up"))
	}
	for _, l := range fp {
		b = append(b, tui.Text("   "+l))
	}
	b = append(b, tui.Text(""))
	code := tui.Line{{Text: "Setup code  ", Style: tui.Strong}}
	switch {
	case info.CodeLocked:
		code = append(code, tui.Span{Text: "LOCKED", Style: tui.Alert}, tui.Span{Text: "  after too many wrong tries", Style: tui.Dim})
	case info.SetupCode == "":
		code = append(code, tui.Span{Text: "not ready yet", Style: tui.Dim})
	default:
		code = append(code, tui.Span{Text: strings.ToUpper(info.SetupCode), Style: tui.Accent})
		if !info.CodeExpires.IsZero() {
			code = append(code, tui.Span{Text: "   " + consoleui.Expires(info.CodeExpires.Sub(now)), Style: tui.Dim})
		}
	}
	b = append(b, code, tui.Text(""), c.ProtectionLine(12))
	if errLine != "" {
		b = append(b, tui.Text(""))
		b = append(b, tui.WrapStyled(tui.Alert, errLine, width, "")...)
	}
	p := c.BigPage(b)
	if info.CodeLocked {
		p.Keys = consoleui.Key("N", "Show a new setup code")
	}
	return p
}

// SettingUpPage is setup running in a browser: from where, since when, and
// the step it's at. Until the first admin exists, X stops it and shows a
// new code.
func SettingUpPage(c consoleui.Chrome, info sources.ConsoleInfo, errLine string) tui.Page {
	b := []tui.Line{tui.Styled(tui.Strong, "Setup is running in a browser."), tui.Text("")}
	if info.SetupSource != "" {
		b = append(b, consoleui.Field("From", 12, tui.Span{Text: info.SetupSource}))
	}
	if !info.SetupStarted.IsZero() {
		b = append(b, consoleui.Field("Started", 12, tui.Span{Text: info.SetupStarted.Format("15:04")}))
	}
	if info.SetupStep > 0 {
		at := fmt.Sprintf("Step %d of %d", info.SetupStep, info.SetupSteps)
		if info.StepName != "" {
			at += ": " + info.StepName
		}
		b = append(b, consoleui.Field("Now at", 12, tui.Span{Text: at}))
	}
	if info.FirstAdmin != "" {
		b = append(b, consoleui.Field("First admin", 12, tui.Span{Text: info.FirstAdmin, Style: tui.Strong}))
	}
	b = append(b, tui.Text(""), tui.Styled(tui.Dim, "Nothing to do here."))
	p := c.BigPage(b)
	if info.FirstAdmin == "" {
		p.Body = append(p.Body, tui.Text(""))
		p.Body = append(p.Body, tui.Wrap("If this isn't you, press X: it stops that setup and shows a new code.", width, "")...)
		p.Keys = consoleui.Key("X", "Stop this setup and show a new code")
	}
	if errLine != "" {
		p.Body = append(p.Body, tui.WrapStyled(tui.Alert, errLine, width, "")...)
	}
	return p
}

// FinishPage is setup done: the box moves to normal operation, by a
// restart when it can't without one.
func FinishPage(c consoleui.Chrome, restarting bool, errLine string) tui.Page {
	b := []tui.Line{tui.Styled(tui.OK, "Setup is done. Starting Sneakers-PAM."), tui.Text("")}
	if restarting {
		b = append(b, tui.Wrap("The box restarts once into normal operation. The status screen appears when it's ready.", width, "")...)
	} else {
		b = append(b, tui.Text("The status screen appears when it's ready."))
	}
	if errLine != "" {
		b = append(b, tui.Text(""))
		b = append(b, tui.WrapStyled(tui.Alert, errLine, width, "")...)
	}
	return c.BigPage(b)
}

// ProblemPage is what first boot shows when it can't go on, and why.
func ProblemPage(c consoleui.Chrome, what string) tui.Page {
	return c.BigPage(tui.WrapStyled(tui.Alert, what, width, ""))
}
