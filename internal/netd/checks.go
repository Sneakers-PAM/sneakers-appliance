// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netlink"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/timesync"
)

// How long the checks wait for things still settling.
const (
	dadWait   = 3 * time.Second
	probeWait = 3 * time.Second
)

// Checks runs the first-boot screen's checks on the management interface
// (spec 2, Section 2.2): link, address (DAD done for IPv6), gateway, each
// DNS server, and the NTP offset. Only "no address at all" can't be
// skipped.
func (d *Daemon) Checks(ctx context.Context) []Check {
	started := time.Now()
	d.mu.Lock()
	s, dns, _, ntp, _, _ := d.effective()
	eng := d.ntp
	d.mu.Unlock()
	name := s.Management.Name
	var out []Check

	link := Check{Name: "link", State: CheckOK, Detail: name + " has a link", Skippable: true}
	links, err := d.o.Sys.Links()
	if i := slices.IndexFunc(links, func(l Link) bool { return l.Name == name }); err != nil || i < 0 || !links[i].Up {
		link = Check{Name: "link", State: CheckFailed, Code: sym(codes.NetNoAddress), Detail: name + " has no link: check the cable or the virtual switch"}
	}
	out = append(out, link)

	addrs := d.settled(ctx, name)
	have4 := slices.ContainsFunc(addrs, func(a netlink.Addr) bool { return a.Prefix.Addr().Is4() })
	have6 := slices.ContainsFunc(addrs, func(a netlink.Addr) bool { return a.Prefix.Addr().Is6() })
	want4, want6 := s.Management.IPv4.Mode != network.V4Off, s.Management.IPv6.Mode != network.V6Off
	switch {
	case (!want4 || !have4) && (!want6 || !have6):
		out = append(out, Check{Name: "address", State: CheckFailed, Code: sym(codes.NetNoAddress), Detail: name + " has no usable address"})
	default:
		if want4 {
			out = append(out, familyCheck("IPv4", have4, s.Management.IPv4.Mode == network.V4DHCP, addrs, false))
		}
		if want6 {
			out = append(out, familyCheck("IPv6", have6, s.Management.IPv6.Mode == network.V6DHCPv6, addrs, true))
		}
	}

	routes, _ := d.o.Sys.Routes(name)
	for _, fam := range []struct {
		v6   bool
		have bool
		gw   netip.Addr
	}{{false, have4, s.Management.IPv4.Gateway}, {true, have6, s.Management.IPv6.Gateway}} {
		if !fam.have {
			continue
		}
		gw := fam.gw
		if !gw.IsValid() {
			for _, r := range routes {
				if r.Default() && r.Gateway.IsValid() && r.Gateway.Is6() == fam.v6 {
					gw = r.Gateway
					break
				}
			}
		}
		label := "IPv4"
		if fam.v6 {
			label = "IPv6"
		}
		if !gw.IsValid() {
			out = append(out, Check{Name: "gateway", State: CheckWarn, Code: sym(codes.NetGateway), Detail: "no " + label + " default gateway", Skippable: true})
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, probeWait)
		err := d.o.Sys.Reach(pctx, name, gw)
		cancel()
		if err != nil {
			out = append(out, Check{Name: "gateway", State: CheckFailed, Code: sym(codes.NetGateway), Detail: fmt.Sprintf("the gateway %s doesn't answer: %v", gw, err), Skippable: true})
			continue
		}
		out = append(out, Check{Name: "gateway", State: CheckOK, Detail: "the gateway " + gw.String() + " answers", Skippable: true})
	}

	query := "example.org"
	for _, n := range ntp {
		if _, err := netip.ParseAddr(n); err != nil {
			query = n
			break
		}
	}
	if len(dns) == 0 {
		out = append(out, Check{Name: "dns", State: CheckWarn, Code: sym(codes.NetDNS), Detail: "no DNS server is set or offered", Skippable: true})
	}
	for _, srv := range dns {
		pctx, cancel := context.WithTimeout(ctx, probeWait)
		err := d.o.Sys.QueryDNS(pctx, srv, query)
		cancel()
		if err != nil {
			out = append(out, Check{Name: "dns", State: CheckFailed, Code: sym(codes.NetDNS), Detail: fmt.Sprintf("the DNS server %s didn't answer for %s: %v", srv, query, err), Skippable: true})
			continue
		}
		out = append(out, Check{Name: "dns", State: CheckOK, Detail: fmt.Sprintf("the DNS server %s answers", srv), Skippable: true})
	}

	out = append(out, ntpCheck(ctx, eng))
	for _, c := range out {
		d.o.Logger.Debug("netd: check", log.F("check", c.Name), log.F("state", string(c.State)), log.F("code", c.Code), log.F("detail", c.Detail))
	}
	d.o.Logger.Info("netd: checks run", log.F("checks", len(out)), log.F("ms", time.Since(started).Milliseconds()))
	return out
}

func sym(code int) string { return codes.Symbol(code) }

// settled is name's usable addresses once DAD has finished (or dadWait
// passed).
func (d *Daemon) settled(ctx context.Context, name string) []netlink.Addr {
	deadline := time.Now().Add(dadWait)
	for {
		addrs, _ := d.o.Sys.Addrs(name)
		tentative := false
		var ok []netlink.Addr
		for _, a := range addrs {
			switch {
			case a.Prefix.Addr().IsLinkLocalUnicast(), a.DADFailed():
			case a.Tentative():
				tentative = true
			default:
				ok = append(ok, a)
			}
		}
		if !tentative || time.Now().After(deadline) || ctx.Err() != nil {
			return ok
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func familyCheck(label string, have, dhcp bool, addrs []netlink.Addr, v6 bool) Check {
	if have {
		var list []string
		for _, a := range addrs {
			if a.Prefix.Addr().Is6() == v6 {
				list = append(list, a.Prefix.String())
			}
		}
		return Check{Name: "address", State: CheckOK, Detail: fmt.Sprintf("%s address %v", label, list), Skippable: true}
	}
	detail := "no " + label + " address yet"
	if dhcp {
		detail = "no " + label + " address yet: no DHCP server answered"
	}
	return Check{Name: "address", State: CheckWarn, Code: sym(codes.NetDHCPTimeout), Detail: detail, Skippable: true}
}

func ntpCheck(ctx context.Context, eng TimeSync) Check {
	if eng == nil {
		return Check{Name: "ntp", State: CheckWarn, Code: sym(codes.NetNTP), Detail: "no time server is set or offered", Skippable: true}
	}
	st := eng.Status()
	if st.State == timesync.StatePending || st.State == timesync.StateUnsynced {
		eng.SyncNow(ctx)
		st = eng.Status()
	}
	switch st.State {
	case timesync.StateSynced:
		return Check{Name: "ntp", State: CheckOK, Detail: fmt.Sprintf("synced with %s, offset %s", st.LastServer, st.LastOffset.Round(time.Millisecond)), Skippable: true}
	case timesync.StateNotConfigured:
		return Check{Name: "ntp", State: CheckWarn, Code: sym(codes.NetNTP), Detail: "no time server is set or offered", Skippable: true}
	default:
		return Check{Name: "ntp", State: CheckFailed, Code: sym(codes.NetNTP), Detail: "the clock isn't synced: " + st.LastError, Skippable: true}
	}
}
