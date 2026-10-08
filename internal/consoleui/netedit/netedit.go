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

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/sources"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/tui"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

const width = consoleui.Width

// Deps are what the editor reads and drives.
type Deps struct {
	Chrome  consoleui.Chrome
	Network sources.Network
	Logger  log.Logger
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
	nics    []sources.NIC
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
	if !settled {
		return c.Page(b, consoleui.Key("E", "Edit"), "")
	}
	return c.Page(b, consoleui.Keys(consoleui.Key("Enter", "Use these settings"), consoleui.Key("E", "Edit")), "")
}

// Edit sets an address by hand and checks it. kept reports the address
// is in use; false is back to the no-address screen.
func Edit(ctx context.Context, u *tui.UI, d Deps) (bool, error) {
	if d.Logger == nil {
		d.Logger = log.Nop()
	}
	nics, err := d.Network.Interfaces(ctx)
	if err != nil {
		return false, err
	}
	f := form{nics: nics}
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
			kept, back, err := apply(ctx, u, d, f)
			if err != nil || kept {
				return kept, err
			}
			if back {
				i = 0
				continue
			}
			i--
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

// Settings is the form as netd settings: the static address on its
// family, the other family left as it comes.
func (f form) settings() network.Settings {
	s := network.Defaults(f.port)
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

// apply sets the address live, shows the checks, and keeps it on Enter.
// back is E (edit from the first field).
func apply(ctx context.Context, u *tui.UI, d Deps, f form) (kept, back bool, err error) {
	s := f.settings()
	if verr := network.Validate(s); verr != nil {
		_, _, err := u.Ask(ctx, tui.Static(ChecksPage(d.Chrome, nil, consoleui.Describe(verr), true)))
		return false, true, err
	}
	token, revert, serr := d.Network.Set(ctx, s)
	if serr != nil {
		d.Logger.Warn("netedit: the address wasn't applied", log.F("error", serr.Error()))
		_, _, err := u.Ask(ctx, tui.Static(ChecksPage(d.Chrome, nil, "The address wasn't applied: "+consoleui.Describe(serr), true)))
		return false, true, err
	}
	d.Logger.Info("netedit: address applied; checking", log.F("port", f.port), log.F("revert_after", revert))
	var checks []sources.Check
	errLine := ""
	settled := false
	for {
		line, typed, err := u.Ask(ctx, func() (tui.Page, bool) {
			if !settled {
				cs, cerr := d.Network.Checks(ctx)
				if cerr != nil {
					errLine = consoleui.Describe(cerr)
				} else {
					checks, errLine = cs, ""
					settled = len(cs) > 0
					for _, c := range cs {
						if c.State == sources.CheckRunning {
							settled = false
						}
					}
				}
			}
			return ChecksPage(d.Chrome, checks, errLine, settled), false
		})
		if err != nil {
			return false, false, err
		}
		if !typed {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "e":
			return false, true, nil
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
			if err := d.Network.Confirm(ctx, token); err != nil {
				errLine = "The address couldn't be kept: " + consoleui.Describe(err)
				continue
			}
			d.Logger.Info("netedit: address kept", log.F("port", f.port))
			return true, false, nil
		}
	}
}
