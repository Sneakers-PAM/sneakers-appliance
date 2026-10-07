// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package enrolment is the console side of the SSH key enrolment window:
// first boot's admin step and the dashboard's Recover access. The window
// itself is accessd's; the console shows the code, takes the typed yes,
// and offers keys typed or fetched on the console.
package enrolment

import (
	"fmt"
	"net/netip"
	"time"

	accessv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/access/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
)

// PageFunc frames a body: the wizard adds its step strip, the dashboard
// its own title.
type PageFunc func(title string, body []tui.Line, keys, prompt string) tui.Page

const width = consoleui.Width

// recoveryNotice is said on every Recover access screen.
const recoveryNotice = "Recover access is recorded in the OS audit log, every other owner sees a banner on :8443, and the key can't approve elevations for 24 hours (another owner can lift that)."

// Title is the window's page title.
func Title(w *accessv1.Enrolment) string {
	if w.GetRecovery() {
		return "Recover access"
	}
	return "Setup: first admin"
}

// Waiting is what the waiting screen shows.
type Waiting struct {
	W *accessv1.Enrolment
	// Addresses are the management addresses; AddrErr is why there are
	// none (the network service isn't installed, say).
	Addresses []string
	AddrErr   error
	// SSHErr is why `ssh enrol@` can't connect (the SSH service isn't
	// installed, say); nil when sshd runs.
	SSHErr error
	// Note is a passing remark (a new code after three wrong ones); Err
	// the last action's error.
	Note, Err string
}

// Hosts turns management addresses (with or without a prefix length) into
// what `ssh enrol@` takes, leaving out link-local ones.
func Hosts(addrs []string) []string {
	var out []string
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			p, perr := netip.ParsePrefix(a)
			if perr != nil {
				continue
			}
			ip = p.Addr()
		}
		if ip.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, ip.String())
	}
	return out
}

func keyLine(k *accessv1.EnrolmentKey) string {
	s := fmt.Sprintf("%s (%s", k.GetFingerprint(), k.GetType())
	if k.GetComment() != "" {
		s += ", comment " + k.GetComment()
	}
	return s + ")"
}

func from(k *accessv1.EnrolmentKey) string {
	switch k.GetVia() {
	case access.ViaTyped:
		return "typed on the console"
	case access.ViaURL:
		return "fetched on the console"
	}
	return "from " + k.GetSourceAddress()
}

// WaitingPage is the window open and waiting: how to connect, the code,
// the host keys to check, and the keys enrolled so far.
func WaitingPage(pf PageFunc, v Waiting, now time.Time) tui.Page {
	w := v.W
	var b []tui.Line
	b = append(b, tui.Text(fmt.Sprintf("Enrol an SSH key for owner %s.", w.GetAdmin())))
	hosts := Hosts(v.Addresses)
	switch {
	case v.SSHErr != nil:
		b = append(b, tui.WrapStyled(tui.Warn, "! "+v.SSHErr.Error()+", so ssh enrol@ can't connect yet. Type or fetch the key on this console instead (t or f).", width, "")...)
	case len(hosts) == 0:
		msg := "! The box has no management address yet"
		if v.AddrErr != nil {
			msg += ": " + v.AddrErr.Error()
		}
		b = append(b, tui.WrapStyled(tui.Warn, msg+". Type or fetch the key on this console instead (t or f).", width, "")...)
	default:
		b = append(b, tui.Text("From the admin's machine run, and check the host key on first connect:"))
		for i, h := range hosts {
			if i == 2 {
				break
			}
			b = append(b, tui.Line{{Text: "    "}, {Text: "ssh enrol@" + h, Style: tui.Bold}})
		}
	}
	b = append(b, consoleui.Field("Code", 12, tui.Span{Text: w.GetCode(), Style: tui.Title},
		tui.Span{Text: fmt.Sprintf("   %d wrong code(s) left", w.GetAttemptsLeft())}))
	for i, k := range w.GetHostKeys() {
		label := ""
		if i == 0 {
			label = "Host keys"
		}
		b = append(b, consoleui.Field(label, 12, tui.Span{Text: fmt.Sprintf("%-12s %s", k.GetType(), k.GetFingerprint())}))
	}
	if t := w.GetIdleUntil(); t != nil {
		left := t.AsTime().Sub(now).Round(time.Minute)
		b = append(b, tui.Text(fmt.Sprintf("The window closes after %d idle minutes (at %s UTC).", int(left.Minutes()), t.AsTime().UTC().Format("15:04"))))
	}
	if w.GetAttemptsLeft() < 3 && w.GetAttemptsLeft() > 0 {
		b = append(b, tui.Styled(tui.Warn, fmt.Sprintf("! %d wrong code(s) so far. After three the window closes and a new code is shown.", 3-w.GetAttemptsLeft())))
	}
	var done []*accessv1.EnrolmentKey
	for _, k := range w.GetKeys() {
		if k.GetState() == "accepted" {
			done = append(done, k)
		}
	}
	if len(done) > 0 {
		b = append(b, tui.Text(fmt.Sprintf("Keys enrolled so far: %d", len(done))))
		for _, k := range done {
			b = append(b, tui.Styled(tui.OK, "  "+keyLine(k)))
		}
	}
	if w.GetRecovery() {
		b = append(b, tui.WrapStyled(tui.Warn, recoveryNotice, width, "")...)
	}
	if v.Note != "" {
		b = append(b, tui.Styled(tui.Warn, v.Note))
	}
	if v.Err != "" {
		b = append(b, tui.WrapStyled(tui.Alert, v.Err, width, "")...)
	}
	keys := "t: type a key   f: fetch keys from a URL"
	if len(done) > 0 {
		keys += "   d: done"
	}
	return pf(Title(w), b, keys, "> ")
}

// OfferedPage is a key that gave the right code (or was typed or fetched
// here), waiting for the typed yes.
func OfferedPage(pf PageFunc, w *accessv1.Enrolment, k *accessv1.EnrolmentKey, errLine string) tui.Page {
	b := []tui.Line{
		tui.Text("This key wants to be a key of admin " + w.GetAdmin() + ":"),
		tui.Styled(tui.Bold, "  "+k.GetFingerprint()),
		tui.Text(fmt.Sprintf("  %s, comment %q, %s", k.GetType(), k.GetComment(), from(k))),
		tui.Text(""),
		tui.Text("Check the fingerprint with the admin. Accept it? Type yes to store it, or no."),
	}
	if w.GetRecovery() {
		b = append(b, tui.Text(""))
		b = append(b, tui.WrapStyled(tui.Warn, recoveryNotice, width, "")...)
	}
	if errLine != "" {
		b = append(b, tui.Text(""))
		b = append(b, tui.WrapStyled(tui.Alert, errLine, width, "")...)
	}
	return pf(Title(w), b, "yes: store the key   no: refuse it", "> ")
}

var closedWhy = map[string]string{
	"idle":     "nothing happened for 30 minutes",
	"attempts": "three wrong codes were typed",
	"done":     "Done was pressed",
}

// ClosedPage is a window that closed by itself.
func ClosedPage(pf PageFunc, w *accessv1.Enrolment) tui.Page {
	why := closedWhy[w.GetClosedReason()]
	if why == "" {
		why = "it was closed"
	}
	b := []tui.Line{
		tui.Text("The enrolment window closed: " + why + "."),
		tui.Text("A new window needs a new code."),
	}
	if n := w.GetEnrolled(); n > 0 {
		b = append(b, tui.Text(fmt.Sprintf("Keys enrolled in it: %d.", n)))
	}
	return pf(Title(w), b, "Enter: open a new window with a new code", "> ")
}

// TypePage takes one public key typed or pasted on the console.
func TypePage(pf PageFunc, w *accessv1.Enrolment, errLine string) tui.Page {
	b := []tui.Line{tui.Text("Type or paste one public key on one line, for example:"),
		tui.Text("  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@laptop"),
		tui.Text("Its fingerprint is shown back for checking before it's stored."),
		tui.Text("Accepted: ssh-ed25519, ecdsa-sha2-nistp256/384, their sk- forms, RSA 3072+.")}
	if errLine != "" {
		b = append(b, tui.Text(""))
		b = append(b, tui.WrapStyled(tui.Alert, errLine, width, "")...)
	}
	return pf(Title(w), b, "Enter alone: back", "key: ")
}

// URLPage takes the https URL of a published key list.
func URLPage(pf PageFunc, w *accessv1.Enrolment, errLine string) tui.Page {
	b := []tui.Line{tui.Text("Fetch the admin's published keys (authorized_keys format) over https, for"),
		tui.Text("example a code forge's https://forge.example.org/alice.keys"),
		tui.Text("This needs the box to reach the internet; on an air-gapped box type the key.")}
	if errLine != "" {
		b = append(b, tui.Text(""))
		b = append(b, tui.WrapStyled(tui.Alert, errLine, width, "")...)
	}
	return pf(Title(w), b, "Enter alone: back", "URL: ")
}

// FetchingPage is shown while the fetch runs.
func FetchingPage(pf PageFunc, w *accessv1.Enrolment, url string) tui.Page {
	return pf(Title(w), []tui.Line{tui.Text("Fetching " + url + " ...")}, "", "")
}

// FetchedPage lists what a fetch found; each key is then confirmed with a
// typed yes.
func FetchedPage(pf PageFunc, w *accessv1.Enrolment, url string, f access.Fetched) tui.Page {
	b := []tui.Line{tui.Text(fmt.Sprintf("%s has %d acceptable key(s):", url, len(f.Keys)))}
	for _, k := range f.Keys {
		b = append(b, tui.Text(fmt.Sprintf("  %s (%s, %s)", k.Fingerprint, k.Type, k.Comment)))
	}
	if len(f.Refused) > 0 {
		b = append(b, tui.Text(fmt.Sprintf("%d other line(s) were refused:", len(f.Refused))))
		for _, r := range f.Refused {
			b = append(b, tui.Styled(tui.Warn, "  "+r))
		}
	}
	b = append(b, tui.Text(""), tui.Text("Each key is shown next, to be accepted with a typed yes or refused."))
	return pf(Title(w), b, "Enter: confirm them one by one", "> ")
}

// FetchFailedPage is a fetch that found nothing.
func FetchFailedPage(pf PageFunc, w *accessv1.Enrolment, url string, err error) tui.Page {
	b := []tui.Line{tui.Text("Fetching " + url + " failed:")}
	b = append(b, tui.WrapStyled(tui.Alert, err.Error(), width, "  ")...)
	b = append(b, tui.Text(""), tui.Text("Without a route to the internet the fetch can't work; type the key instead."))
	return pf(Title(w), b, "Enter: back", "> ")
}
