// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package wizard is first boot on the console: the network, the
// protection chosen at boot, the first admin and the SSH key enrolment,
// then the hand-off to :8443 for the recovery keys and the first sign-in.
package wizard

import (
	"fmt"
	"strings"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

const width = consoleui.Width

// Step is one first-boot step, numbered as Section 2.1 numbers them.
type Step int

// The steps.
const (
	StepNetwork Step = iota + 1
	StepProtection
	StepAdmin
	StepRecovery
	StepSignIn
	StepDone
)

var stepTitles = map[Step]string{
	StepNetwork:    "Setup 1 of 5: network",
	StepProtection: "Setup 2 of 5: protection",
	StepAdmin:      "Setup 3 of 5: first admin",
	StepRecovery:   "Setup 4 and 5: continue on :8443",
	StepSignIn:     "Setup 4 and 5: continue on :8443",
	StepDone:       "Setup complete",
}

// Frame is a wizard page: the shared chrome, the step strip on top of the
// body.
type Frame struct {
	Chrome consoleui.Chrome
	Step   Step
	Done   []bool
}

// Page frames body.
func (f Frame) Page(body []tui.Line, keys, prompt string) tui.Page {
	b := append([]tui.Line{consoleui.Steps(int(f.Step), f.Done), tui.Text("")}, body...)
	return f.Chrome.Page(stepTitles[f.Step], b, keys, prompt)
}

func errLines(e string) []tui.Line {
	if e == "" {
		return nil
	}
	return append([]tui.Line{tui.Text("")}, tui.WrapStyled(tui.Alert, e, width, "")...)
}

// NoLink reports that no interface has a link, as far as is known: every
// one is up and none has a carrier.
func NoLink(nics []sources.NIC) bool {
	for _, n := range nics {
		if n.Link || !n.Up {
			return false
		}
	}
	return true
}

// NICsPage lists the interfaces to pick the management one from (or the
// service one, with service set).
func NICsPage(f Frame, nics []sources.NIC, service bool, mgmt string, errLine string) tui.Page {
	var b []tui.Line
	if NoLink(nics) {
		b = append(b, tui.Styled(tui.Alert, "No network interface has a link."))
		b = append(b, tui.Wrap("Connect the cable, or the VM's network adapter, then press Enter to look again. Setup can't go on without a link.", width, "")...)
		b = append(b, tui.Text(""))
	} else if service {
		b = append(b, tui.Wrap("The service interface carries the product (443 and 80). Type its number, or press Enter to share "+mgmt+" with the management traffic.", width, "")...)
	} else {
		b = append(b, tui.Wrap("Choose the management interface: ports 22 and 8443 listen only there. Type its number and press Enter (Enter alone takes 1).", width, "")...)
	}
	b = append(b, tui.Text(""))
	down := false
	for i, n := range nics {
		link, st := "no link", tui.Warn
		switch {
		case n.Link:
			link, st = "link up", tui.OK
		case !n.Up:
			link, st, down = "not up", tui.Normal, true
		}
		drv := n.Driver
		if drv == "" {
			drv = "-"
		}
		b = append(b, tui.Line{{Text: fmt.Sprintf("  %d  %-10s %-18s ", i+1, n.Name, n.MAC)}, {Text: fmt.Sprintf("%-8s", link), Style: st}, {Text: "  " + drv}})
	}
	if down {
		b = append(b, tui.Text(""))
		b = append(b, tui.Wrap("An interface that's not up yet has an unknown link: the network service brings it up.", width, "")...)
	}
	b = append(b, errLines(errLine)...)
	keys := "number: choose   Enter: the first one"
	switch {
	case NoLink(nics):
		keys = "Enter: look again"
	case service:
		keys = "number: a separate service interface   Enter: share " + mgmt
	}
	return f.Page(b, keys, "> ")
}

// CurrentPage is the address netd took by itself on its first start,
// offered to keep.
func CurrentPage(f Frame, a sources.Addresses, err error) tui.Page {
	var b []tui.Line
	hosts := hostsOf(a.Management)
	switch {
	case err != nil:
		b = append(b, tui.WrapStyled(tui.Alert, "The network service isn't answering: "+consoleui.Describe(err), width, "")...)
	case len(hosts) == 0:
		b = append(b, tui.Text("Waiting for an address: the network service is asking DHCP and router"))
		b = append(b, tui.Text("advertisements on the first interface with a link ..."))
	default:
		b = append(b, tui.Text("The box took an address by itself (DHCP and SLAAC on the first linked NIC):"))
		for _, m := range a.Management {
			b = append(b, tui.Styled(tui.Bold, "    "+m))
		}
		if a.Hostname != "" {
			b = append(b, consoleui.Field("Host name", 12, tui.Span{Text: a.Hostname}))
		}
		b = append(b, tui.Text(""), tui.Text("Press Enter to keep it (the connection is checked first), or e to choose the"), tui.Text("interface and the settings."))
	}
	keys := "e: choose the interface and settings"
	if len(hosts) > 0 && err == nil {
		keys = "Enter: keep this address   " + keys
	}
	return f.Page(b, keys, "> ")
}

// Form is the network settings being edited.
type Form struct {
	S network.Settings
}

func v4(i network.Interface) string {
	switch i.IPv4.Mode {
	case network.V4Static:
		s := "static " + i.IPv4.Address.String()
		if i.IPv4.Gateway.IsValid() {
			s += " via " + i.IPv4.Gateway.String()
		}
		return s
	case network.V4Off:
		return "off"
	}
	return "DHCP"
}

func v6(i network.Interface) string {
	switch i.IPv6.Mode {
	case network.V6Static:
		s := "static " + i.IPv6.Address.String()
		if i.IPv6.Gateway.IsValid() {
			s += " via " + i.IPv6.Gateway.String()
		}
		return s
	case network.V6DHCPv6:
		return "DHCPv6"
	case network.V6Off:
		return "off"
	}
	return "SLAAC (and RDNSS)"
}

func orDHCP(vals []string, what string) string {
	if len(vals) == 0 {
		return what
	}
	return strings.Join(vals, " ")
}

// SettingsPage shows the settings with a number per field.
func SettingsPage(f Frame, form Form, errLine string) tui.Page {
	s := form.S
	svc := "the same interface"
	if s.Service != nil {
		svc = s.Service.Name
	}
	host := s.Hostname
	if host == "" {
		host = "from DHCP"
	}
	var dns []string
	for _, a := range s.DNS {
		dns = append(dns, a.String())
	}
	b := []tui.Line{
		tui.Text(fmt.Sprintf("Management interface %s; the product's traffic: %s.", s.Management.Name, svc)),
		tui.Text(""),
		tui.Text("  1  IPv4       " + v4(s.Management)),
		tui.Text("  2  IPv6       " + v6(s.Management)),
		tui.Text("  3  Host name  " + host),
		tui.Text("  4  DNS        " + orDHCP(dns, "from DHCP and router advertisements")),
		tui.Text("  5  NTP        " + orDHCP(s.NTP, "from DHCP")),
		tui.Text(""),
		tui.Text("Type a number to change it, or press Enter to apply these settings."),
		tui.Text("They apply live, then the box checks the link, address, gateway, DNS and NTP."),
	}
	b = append(b, errLines(errLine)...)
	return f.Page(b, "1-5: change   Enter: apply", "> ")
}

// FieldHelp is what each field takes.
var FieldHelp = map[int][2]string{
	1: {"IPv4", "dhcp, off, or static with the address/prefix and the gateway: static 192.0.2.10/24 192.0.2.1"},
	2: {"IPv6", "slaac, dhcpv6, off, or static with the address/prefix and the gateway: static 2001:db8::10/64 2001:db8::1"},
	3: {"Host name", "a fully qualified name such as appliance.example.org, or Enter alone for the one DHCP offers"},
	4: {"DNS", "up to three server addresses separated by spaces, or Enter alone for the ones DHCP offers"},
	5: {"NTP", "up to four servers (names or addresses) separated by spaces, or Enter alone for the ones DHCP offers"},
}

// FieldPage edits one field.
func FieldPage(f Frame, field int, errLine string) tui.Page {
	h := FieldHelp[field]
	b := append([]tui.Line{tui.Styled(tui.Bold, h[0])}, tui.Wrap(h[1], width, "")...)
	b = append(b, errLines(errLine)...)
	return f.Page(b, "Enter the new value", strings.ToLower(h[0])+": ")
}

// NotInstalledPage is the network step while netd isn't in the build: the
// settings can't be applied and nothing pretends they were.
func NotInstalledPage(f Frame, err error) tui.Page {
	b := []tui.Line{tui.Styled(tui.Alert, err.Error()+".")}
	b = append(b, tui.Wrap("The settings can't be applied, so the box has no address on the management interface and setup can't go on past this step. Nothing was changed.", width, "")...)
	return f.Page(b, "e: edit the settings   r: try again", "> ")
}

var checkStyle = map[string]tui.Style{sources.CheckOK: tui.OK, sources.CheckWarn: tui.Warn, sources.CheckFailed: tui.Alert}

// ChecksPage is the checks running, then their results.
func ChecksPage(f Frame, checks []sources.Check, revert int, errLine string) tui.Page {
	head := "Checking the connection:"
	if revert > 0 {
		head = fmt.Sprintf("Applied. Checking the connection (the change reverts in %d s unless kept):", revert)
	}
	b := []tui.Line{tui.Text(head), tui.Text("")}
	running, failed, blocked := len(checks) == 0, false, false
	for _, c := range checks {
		st := c.State
		if st == sources.CheckRunning {
			running = true
		}
		if st == sources.CheckFailed {
			failed = true
			if !c.Skippable {
				blocked = true
			}
		}
		detail := c.Detail
		if c.Code != "" && st != sources.CheckOK {
			detail += " (" + c.Code + ")"
		}
		b = append(b, tui.Line{{Text: "  "}, {Text: fmt.Sprintf("%-8s", st), Style: checkStyle[st]}, {Text: fmt.Sprintf("%-9s %s", c.Name, detail)}})
	}
	b = append(b, tui.Text(""))
	keys := ""
	switch {
	case running:
		b = append(b, tui.Text("Checking ..."))
	case blocked:
		b = append(b, tui.WrapStyled(tui.Alert, "The management interface has no address. This can't be skipped: edit the settings.", width, "")...)
		keys = "e: edit the settings"
	case failed:
		b = append(b, tui.Wrap("A check failed. Edit the settings, or continue anyway. A failed or skipped NTP sync stays as a warning on the console and :8443, since elevation certificates and TLS depend on the clock.", width, "")...)
		keys = "e: edit   c: continue anyway"
	default:
		b = append(b, tui.Styled(tui.OK, "Every check passed."))
		keys = "Enter: keep these settings and continue"
	}
	b = append(b, errLines(errLine)...)
	return f.Page(b, keys, "> ")
}

// ProtectionPage is step 2: what was chosen at boot, read-only now.
func ProtectionPage(f Frame, p keycustody.Protection, mode keycustody.Mode) tui.Page {
	st := tui.OK
	if p.Level == keycustody.LevelReduced {
		st = tui.Alert
	}
	b := tui.WrapStyled(st, screens.ProtectionText(p, mode), width, "")
	at := "TPM (sealed to this box's boot chain)"
	if mode == keycustody.ModeKeyfile {
		at = "key file on the disk"
	}
	b = append(b, tui.Text(""), consoleui.Field("At-rest key", 13, tui.Span{Text: at}), tui.Text(""))
	b = append(b, tui.Wrap("The Secure Boot choice and the key custody were made at boot, before this wizard, and the state volumes are formatted for them. The custody is fixed until a reinstall.", width, "")...)
	if r := screens.RaiseText(p); r != "" {
		b = append(b, tui.Text(""))
		b = append(b, tui.WrapStyled(tui.Warn, r, width, "")...)
	}
	return f.Page(b, "Enter: continue", "> ")
}

// AdminPage asks the first admin's name.
func AdminPage(f Frame, errLine string) tui.Page {
	b := tui.Wrap("The first admin is an owner: they add other admins and approve elevated shells. Their name is their login: 2 to 31 lowercase letters, digits, _ or -, starting with a letter. root, maint, enrol, sshd, sshkeys, nobody, osadmin and console are taken.", width, "")
	b = append(b, tui.Text(""))
	b = append(b, tui.Wrap("Next, their SSH key is enrolled: over SSH with a code shown here, or typed or fetched on this console.", width, "")...)
	b = append(b, errLines(errLine)...)
	return f.Page(b, "Enter the name", "admin: ")
}

// Continue is what the :8443 hand-off screen shows.
type Continue struct {
	Addresses []string
	AddrErr   error
	TLS       string
	// OsadminErr is why :8443 isn't up.
	OsadminErr error
	Recovery   []*osadminv1.RecoveryKey
	Max        int32
	Admin      string
	// SetupCode is the one-time code the :8443 setup page asks for, while
	// no browser holds it.
	SetupCode string
	// Err is why setup couldn't complete.
	Err string
}

// ContinuePage is steps 4 and 5: the recovery keys and the first sign-in,
// both on :8443 (the recovery keys also over SSH).
func ContinuePage(f Frame, c Continue) tui.Page {
	var b []tui.Line
	hosts := hostsOf(c.Addresses)
	switch {
	case len(hosts) == 0:
		msg := "The box has no management address yet"
		if c.AddrErr != nil {
			msg += " (" + c.AddrErr.Error() + ")"
		}
		b = append(b, tui.WrapStyled(tui.Alert, msg+", so :8443 can't be reached.", width, "")...)
	default:
		for i, h := range hosts {
			lead := "From the admin's machine open "
			if i > 0 {
				lead = strings.Repeat(" ", len(lead)-3) + "or "
			}
			if i == 2 {
				break
			}
			b = append(b, tui.Line{{Text: lead}, {Text: "https://" + h + ":8443/", Style: tui.Bold}})
		}
	}
	if c.SetupCode != "" {
		b = append(b, tui.Line{{Text: "and type the setup code "}, {Text: c.SetupCode, Style: tui.Bold}})
	}
	if c.OsadminErr != nil {
		b = append(b, tui.WrapStyled(tui.Alert, ":8443 isn't running: "+c.OsadminErr.Error(), width, "")...)
	}
	if c.TLS != "" {
		b = append(b, tui.Text("and check its certificate on the first visit (self-signed for now), SHA-256:"))
		for _, l := range consoleui.FingerprintLines(c.TLS) {
			b = append(b, tui.Text("    "+l))
		}
	}
	rk := fmt.Sprintf("Recovery keys: %d of up to %d", len(c.Recovery), c.Max)
	switch len(c.Recovery) {
	case 0:
		rk += ". Add one on the :8443 setup page, or: ssh " + c.Admin + "@<address> setup recovery-key < backup.pub"
	case 1:
		rk += " (a second, held by someone else, is recommended):"
	default:
		rk += ":"
	}
	b = append(b, tui.Wrap(rk, width, "")...)
	for _, r := range c.Recovery {
		b = append(b, tui.Styled(tui.OK, fmt.Sprintf("  %-8s %s  %s", strings.TrimPrefix(r.GetType(), "ssh-"), r.GetFingerprint(), r.GetLabel())))
	}
	if len(c.Recovery) > 0 {
		b = append(b, tui.Wrap("Then sign in on :8443 and approve its code: ssh "+c.Admin+"@<address> login <code>", width, "")...)
	}
	b = append(b, errLines(c.Err)...)
	return f.Page(b, "waiting for a recovery key and the first sign-in; this moves on by itself", "")
}

// TypedOneAdmin confirms the single-admin warning.
const TypedOneAdmin = "one admin"

// SingleAdminPage is the single-admin warning (spec 2 Section 2.12): with
// one admin there's no quorum, so the operator confirms it explicitly.
func SingleAdminPage(f Frame, errLine string) tui.Page {
	b := tui.WrapStyled(tui.Warn, "This box has one admin. One admin means no quorum: a factory reset then means re-creating the box, never resetting it in place.", width, "")
	b = append(b, tui.Text(""))
	b = append(b, tui.Wrap("To have a quorum, add a second admin on :8443 now. To go on with one admin, type "+TypedOneAdmin+" and press Enter.", width, "")...)
	b = append(b, errLines(errLine)...)
	return f.Page(b, "type "+TypedOneAdmin+" to confirm", "> ")
}

// Complete is the last screen's state.
type Complete struct {
	// Starting while the box moves to normal; Ready once it has.
	Starting, Ready bool
	// HandoverErr is why the box can't move to normal without a restart.
	HandoverErr error
	ProductURL  string
	Err         string
}

// CompletePage is setup done.
func CompletePage(f Frame, c Complete) tui.Page {
	b := []tui.Line{tui.Styled(tui.OK, "Setup is complete."), tui.Text("")}
	b = append(b, tui.Wrap("The appliance admin is ready on :8443. The product's own first-run page comes once the platform runs:", width, "")...)
	if c.ProductURL != "" {
		b = append(b, tui.Text("    "+c.ProductURL))
	}
	b = append(b, tui.Text(""))
	keys, prompt := "", ""
	switch {
	case c.Ready:
		b = append(b, tui.Styled(tui.OK, "The platform is starting in normal operation; this console becomes the dashboard."))
	case c.Starting:
		b = append(b, tui.Text("Starting the platform ..."))
	default:
		msg := "Restart to start normal operation."
		if c.HandoverErr != nil {
			msg += " " + c.HandoverErr.Error() + "."
		}
		b = append(b, tui.Wrap(msg, width, "")...)
		keys, prompt = "reboot: restart now", "> "
	}
	b = append(b, errLines(c.Err)...)
	return f.Page(b, keys, prompt)
}
