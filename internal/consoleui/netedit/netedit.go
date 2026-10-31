// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package netedit is the console's one network screen: shown only when
// DHCP gives the box no address, it lists the ports and sets an address by
// hand, one field at a time, then checks it before keeping it.
package netedit

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

const width = consoleui.Width

// How long the editor waits for netd. A Set or Confirm is a live change on
// the box, and the checks wait on the gateway, DNS and NTP.
const (
	DefaultSetTimeout    = 15 * time.Second
	DefaultChecksTimeout = 20 * time.Second
	DefaultReadTimeout   = 5 * time.Second
)

// What the error page says when netd runs out of time. netd finishes or
// undoes a change whether the console is still waiting or not.
const (
	setTimedOut = "The box didn't answer in time, so the address may not be set. A change nobody keeps goes back on its own."
	// checksTimedOut has the same promise: the token was never confirmed.
	checksTimedOut = "The network checks didn't finish in time. The address wasn't kept, so it goes back on its own."
	noPorts        = "The box didn't answer, so the ports can't be listed right now."
)

// Deps are what the editor reads and drives.
type Deps struct {
	Chrome  consoleui.Chrome
	Network sources.Network
	Logger  log.Logger
	// SetTimeout, ChecksTimeout and ReadTimeout bound one Set or Confirm,
	// one Checks and the first reads; zero is the Default for each.
	SetTimeout, ChecksTimeout, ReadTimeout time.Duration
}

func (d Deps) withDefaults() Deps {
	if d.Logger == nil {
		d.Logger = log.Nop()
	}
	if d.SetTimeout == 0 {
		d.SetTimeout = DefaultSetTimeout
	}
	if d.ChecksTimeout == 0 {
		d.ChecksTimeout = DefaultChecksTimeout
	}
	if d.ReadTimeout == 0 {
		d.ReadTimeout = DefaultReadTimeout
	}
	return d
}

// NoAddressPage says the box has no address and lists its ports: N sets
// one by hand, R tries DHCP again.
func NoAddressPage(c consoleui.Chrome, nics []sources.NIC, errLine string) tui.Page {
	b := []tui.Line{
		tui.Styled(tui.Warn, "This box has no network address yet."),
		tui.Text(""),
	}
	b = append(b, tui.Wrap("No DHCP server answered, so there is no address to show. Give it one by hand.", width, "")...)
	b = append(b, tui.Text(""), tui.Styled(tui.Dim, fmt.Sprintf("   %-9s %-12s %s", "Port", "Cable", "Hardware address")))
	for _, n := range nics {
		cable := tui.Span{Text: fmt.Sprintf("%-12s ", "no cable"), Style: tui.Warn}
		if n.Link {
			cable = tui.Span{Text: fmt.Sprintf("%-12s ", "connected"), Style: tui.OK}
		}
		b = append(b, tui.Line{{Text: fmt.Sprintf("   %-9s ", n.Name)}, cable, {Text: n.MAC}})
	}
	b = appendErr(b, errLine)
	return c.Page(b, consoleui.Keys(consoleui.Key("N", "Set an address by hand"), consoleui.Key("R", "Try DHCP again")), "")
}

func appendErr(b []tui.Line, errLine string) []tui.Line {
	if errLine == "" {
		return b
	}
	return append(append(b, tui.Text("")), tui.WrapStyled(tui.Alert, errLine, width, "")...)
}

// The fields, in order.
const (
	fieldPort = iota
	fieldAddress
	fieldGateway
	fieldDNS
)

var fieldNames = []string{"Port", "Address", "Gateway", "DNS server"}

// form is the address being set by hand.
type form struct {
	nics []sources.NIC
	// base is the box's current settings, which the form changes only
	// where it was edited; zero when netd gave none.
	base    network.Settings
	port    string
	address netip.Prefix
	gateway netip.Addr
	dns     netip.Addr
}

func (f form) value(i int) string {
	switch i {
	case fieldPort:
		return f.port
	case fieldAddress:
		if f.address.IsValid() {
			return f.address.String()
		}
	case fieldGateway:
		if f.gateway.IsValid() {
			return f.gateway.String()
		}
	case fieldDNS:
		if f.dns.IsValid() {
			return f.dns.String()
		}
	}
	return ""
}

func (f form) fields() []int {
	if len(f.nics) > 1 {
		return []int{fieldPort, fieldAddress, fieldGateway, fieldDNS}
	}
	return []int{fieldAddress, fieldGateway, fieldDNS}
}

var fieldHelp = map[int]string{
	fieldPort:    "Type the number of the port to use.",
	fieldAddress: "Type the address for %s with its prefix.",
	fieldGateway: "Type the gateway, or press Enter for none.",
	fieldDNS:     "Type the DNS server, or press Enter for none.",
}

// FieldPage asks for one field, showing the others as they stand.
func FieldPage(c consoleui.Chrome, f form, field, n, of int, errLine string) tui.Page {
	head := "Set an address by hand"
	b := []tui.Line{{{Text: head, Style: tui.Strong}, {Text: fmt.Sprintf("%*s", width-len(head), fmt.Sprintf("field %d of %d", n, of)), Style: tui.Dim}}, tui.Text("")}
	help := fieldHelp[field]
	if strings.Contains(help, "%s") {
		help = fmt.Sprintf(help, f.port)
	}
	b = append(b, tui.Wrap(help, width, "")...)
	b = append(b, tui.Text(""))
	if field == fieldPort {
		for i, nic := range f.nics {
			cable := "no cable"
			if nic.Link {
				cable = "connected"
			}
			b = append(b, tui.Text(fmt.Sprintf("   %d  %-9s %s", i+1, nic.Name, cable)))
		}
	} else {
		for _, i := range f.fields() {
			st := tui.Normal
			if i == field {
				st = tui.Strong
			}
			b = append(b, tui.Line{{Text: fmt.Sprintf("   %-13s", fieldNames[i])}, {Text: f.value(i), Style: st}})
		}
	}
	if field == fieldAddress {
		b = append(b, tui.Text(""), tui.Styled(tui.Dim, "For example 192.0.2.10/24 or 2001:db8::10/64"))
	}
	b = appendErr(b, errLine)
	return c.Page(b, consoleui.Keys(consoleui.Key("Enter", "Next"), consoleui.Key("B", "Back")), fieldNames[field]+": ")
}

// ChecksPage shows the checks of the address set by hand.
func ChecksPage(c consoleui.Chrome, checks []sources.Check, errLine string, settled bool) tui.Page {
	b := []tui.Line{tui.Styled(tui.Strong, "Checking the network"), tui.Text("")}
	if len(checks) == 0 && errLine == "" && !settled {
		b = append(b, tui.Styled(tui.Dim, "Starting the checks."))
	}
	for _, ch := range checks {
		mark, st := "[..]", tui.Dim
		switch ch.State {
		case sources.CheckOK:
			mark, st = "[ok]", tui.OK
		case sources.CheckWarn:
			mark, st = "[!!]", tui.Warn
		case sources.CheckFailed:
			mark, st = "[!!]", tui.Alert
		}
		text := ch.Name
		if ch.Detail != "" && ch.State != sources.CheckOK {
			text += ": " + ch.Detail
		}
		for i, l := range tui.Wrap(text, width-9, "") {
			lead := tui.Line{{Text: "   "}, {Text: mark, Style: st}, {Text: "  "}}
			if i > 0 {
				lead = tui.Text("         ")
			}
			b = append(b, append(lead, l...))
		}
	}
	b = appendErr(b, errLine)
	leave := consoleui.Key("Q", "Leave")
	if !settled {
		return c.Page(b, consoleui.Keys(consoleui.Key("E", "Edit"), leave), "")
	}
	return c.Page(b, consoleui.Keys(consoleui.Key("Enter", "Use these settings"), consoleui.Key("E", "Edit"), leave), "")
}

// ApplyingPage is up while netd sets the address.
func ApplyingPage(c consoleui.Chrome) tui.Page {
	return c.Page([]tui.Line{tui.Styled(tui.Strong, "Setting the address"), tui.Text(""), tui.Text("This takes a few seconds.")}, nil, "")
}

// ErrorPage says why the editor is closing; Enter leaves it.
func ErrorPage(c consoleui.Chrome, errLine string) tui.Page {
	b := append([]tui.Line{tui.Styled(tui.Strong, "The network editor stopped"), tui.Text("")}, tui.WrapStyled(tui.Alert, errLine, width, "")...)
	return c.Page(b, consoleui.Key("Enter", "Leave"), "")
}

// Edit sets an address by hand and checks it. kept reports the address
// is in use; false is back to the screen it was opened from.
func Edit(ctx context.Context, u *tui.UI, d Deps) (bool, error) {
	d = d.withDefaults()
	rc, cancel := context.WithTimeout(ctx, d.ReadTimeout)
	defer cancel()
	nics, err := d.Network.Interfaces(rc)
	if err != nil {
		d.Logger.Warn("netedit: the ports can't be listed", log.F("error", err.Error()))
		_, _, err := u.Ask(ctx, tui.Static(ErrorPage(d.Chrome, noPorts)))
		return false, err
	}
	f := form{nics: nics}
	if cur, err := d.Network.Get(rc); err == nil {
		f.base = cur
	} else {
		d.Logger.Warn("netedit: the current settings can't be read; the address goes on the defaults", log.F("error", err.Error()))
	}
	for _, n := range nics {
		if n.Link {
			f.port = n.Name
			break
		}
	}
	if f.port == "" && len(nics) > 0 {
		f.port = nics[0].Name
	}
	fields := f.fields()
	for i := 0; i >= 0 && i <= len(fields); {
		if i == len(fields) {
			end, err := apply(ctx, u, d, f)
			if err != nil || end != endEdit {
				return end == endKept, err
			}
			i = 0
			continue
		}
		moved, err := ask(ctx, u, d.Chrome, &f, fields[i], i+1, len(fields))
		if err != nil {
			return false, err
		}
		i += moved
	}
	return false, nil
}

// ask reads one field: +1 is on to the next, -1 back.
func ask(ctx context.Context, u *tui.UI, c consoleui.Chrome, f *form, field, n, of int) (int, error) {
	errLine := ""
	for {
		line, _, err := u.Ask(ctx, tui.Static(FieldPage(c, *f, field, n, of, errLine)))
		if err != nil {
			return 0, err
		}
		line = strings.TrimSpace(line)
		if strings.EqualFold(line, "b") {
			return -1, nil
		}
		if err := f.set(field, line); err != nil {
			errLine = err.Error()
			continue
		}
		return 1, nil
	}
}

func (f *form) set(field int, line string) error {
	switch field {
	case fieldPort:
		if line == "" && f.port != "" {
			return nil
		}
		i, err := strconv.Atoi(line)
		if err != nil || i < 1 || i > len(f.nics) {
			return fmt.Errorf("type a number from 1 to %d", len(f.nics))
		}
		f.port = f.nics[i-1].Name
	case fieldAddress:
		if line == "" && f.address.IsValid() {
			return nil
		}
		p, err := netip.ParsePrefix(line)
		if err != nil || p.Addr().IsLinkLocalUnicast() || p.Addr().IsUnspecified() {
			return fmt.Errorf("%q isn't an address with its prefix, such as 192.0.2.10/24", line)
		}
		f.address = p
	case fieldGateway, fieldDNS:
		var a netip.Addr
		if line != "" {
			var err error
			if a, err = netip.ParseAddr(line); err != nil {
				return fmt.Errorf("%q isn't an IPv4 or IPv6 address", line)
			}
		}
		if field == fieldGateway {
			if a.IsValid() && a.Is4() != f.address.Addr().Is4() {
				return errors.New("the gateway must be the same kind of address as the box's")
			}
			f.gateway = a
		} else {
			f.dns = a
		}
	}
	return nil
}

// Settings is the form as netd settings: the box's current settings with
// the static address on its family and, when one was typed, the DNS
// server. On another port than the current one that port's families start
// from the defaults; everything else (NTP, the host name, the search
// domains, the allow-list, the time zone, the proxy, the cluster ranges)
// stays as it was.
func (f form) settings() network.Settings {
	s := f.base
	if s.Management.Name == "" {
		s = network.Defaults(f.port)
	}
	if s.Management.Name != f.port {
		s.Management = network.Defaults(f.port).Management
	}
	if f.address.Addr().Is4() {
		s.Management.IPv4 = network.Family4{Mode: network.V4Static, Address: f.address, Gateway: f.gateway}
	} else {
		s.Management.IPv6 = network.Family6{Mode: network.V6Static, Address: f.address, Gateway: f.gateway}
	}
	if f.dns.IsValid() {
		s.DNS = []netip.Addr{f.dns}
	}
	return s
}

// How apply ended.
const (
	endKept = iota
	endEdit
	endLeave
)

// checkRun is one Checks call's result.
type checkRun struct {
	checks  []sources.Check
	err     error
	expired bool
}

// runChecks makes one Checks call off the console's loop, so the page keeps
// drawing and reading keys, and sends its result to done.
func runChecks(ctx context.Context, d Deps, done chan<- checkRun) {
	c, cancel := context.WithTimeout(ctx, d.ChecksTimeout)
	defer cancel()
	cs, err := d.Network.Checks(c)
	done <- checkRun{checks: cs, err: err, expired: err != nil && errors.Is(c.Err(), context.DeadlineExceeded)}
}

// failed shows errLine on the checks page: Q leaves, anything else edits.
func failed(ctx context.Context, u *tui.UI, d Deps, errLine string) (int, error) {
	line, _, err := u.Ask(ctx, tui.Static(ChecksPage(d.Chrome, nil, errLine, true)))
	if strings.EqualFold(strings.TrimSpace(line), "q") {
		return endLeave, err
	}
	return endEdit, err
}

// apply sets the address live, shows the checks, and keeps it on Enter. The
// checks run in the background; E edits from the first field and Q leaves,
// and an address left unconfirmed goes back on its own. A call that runs
// out of time ends on the error page.
func apply(ctx context.Context, u *tui.UI, d Deps, f form) (int, error) {
	s := f.settings()
	if verr := network.Validate(s); verr != nil {
		return failed(ctx, u, d, consoleui.Describe(verr))
	}
	u.Show(ApplyingPage(d.Chrome))
	sc, cancelSet := context.WithTimeout(ctx, d.SetTimeout)
	token, revert, serr := d.Network.Set(sc, s)
	expired := errors.Is(sc.Err(), context.DeadlineExceeded)
	cancelSet()
	if serr != nil {
		d.Logger.Warn("netedit: the address wasn't applied", log.F("error", serr.Error()), log.F("timed_out", expired))
		if expired {
			_, _, err := u.Ask(ctx, tui.Static(ErrorPage(d.Chrome, setTimedOut)))
			return endLeave, err
		}
		return failed(ctx, u, d, "The address wasn't applied: "+consoleui.Describe(serr))
	}
	d.Logger.Info("netedit: address applied; checking", log.F("port", f.port), log.F("revert_after", revert))
	runs, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan checkRun, 1)
	running := false
	var checks []sources.Check
	errLine := ""
	settled := false
	view := func() (tui.Page, bool) {
		select {
		case r := <-done:
			running = false
			switch {
			case r.expired:
				return tui.Page{}, true
			case r.err != nil:
				errLine = consoleui.Describe(r.err)
			default:
				checks, errLine = r.checks, ""
				settled = len(r.checks) > 0
				for _, c := range r.checks {
					if c.State == sources.CheckRunning {
						settled = false
					}
				}
			}
		default:
		}
		if !settled && !running {
			running = true
			go runChecks(runs, d, done)
		}
		return ChecksPage(d.Chrome, checks, errLine, settled), false
	}
	for {
		line, typed, err := u.Ask(ctx, view)
		if err != nil {
			return endLeave, err
		}
		if !typed {
			d.Logger.Warn("netedit: the checks ran out of time", log.F("port", f.port))
			_, _, err := u.Ask(ctx, tui.Static(ErrorPage(d.Chrome, checksTimedOut)))
			return endLeave, err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "e":
			return endEdit, nil
		case "q":
			d.Logger.Info("netedit: left without keeping the address", log.F("port", f.port))
			return endLeave, nil
		case "":
			if !settled {
				continue
			}
			for _, c := range checks {
				if c.State == sources.CheckFailed && !c.Skippable {
					errLine = "The address can't be used while " + c.Name + " fails. Press E to change it."
					settled = false
				}
			}
			if !settled {
				settled = true
				continue
			}
			cc, cancel := context.WithTimeout(ctx, d.SetTimeout)
			err := d.Network.Confirm(cc, token)
			cancel()
			if err != nil {
				errLine = "The address couldn't be kept: " + consoleui.Describe(err)
				continue
			}
			d.Logger.Info("netedit: address kept", log.F("port", f.port))
			return endKept, nil
		}
	}
}
