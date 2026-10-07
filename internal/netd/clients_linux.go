// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netd

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/nclient6"
	"github.com/mdlayher/ndp"
)

// Retry limits for the clients.
const (
	retryMin = 2 * time.Second
	retryMax = time.Minute
)

// Clients are the real DHCPv4 (insomniacslk/dhcp nclient4), DHCPv6
// (nclient6) and router advertisement (mdlayher/ndp) clients.
type Clients struct {
	Logger log.Logger
}

func (c Clients) lg() log.Logger {
	if c.Logger == nil {
		return log.Nop()
	}
	return c.Logger
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func backoff(d time.Duration) time.Duration { return min(max(2*d, retryMin), retryMax) }

func addrOf(ip net.IP) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(ip)
	return a.Unmap(), ok && a.IsValid()
}

func addrsOf(ips []net.IP) []netip.Addr {
	var out []netip.Addr
	for _, ip := range ips {
		if a, ok := addrOf(ip); ok && !a.IsUnspecified() {
			out = append(out, a)
		}
	}
	return out
}

func strings4(ips []net.IP) []string {
	var out []string
	for _, a := range addrsOf(ips) {
		out = append(out, a.String())
	}
	return out
}

func lease4(ack *dhcpv4.DHCPv4) (*Lease4, error) {
	ip, ok := addrOf(ack.YourIPAddr)
	if !ok || !ip.Is4() {
		return nil, errors.New("the ACK carries no address")
	}
	mask := ack.SubnetMask()
	bits := 24
	if mask != nil {
		bits, _ = mask.Size()
	}
	l := &Lease4{
		Addr:     netip.PrefixFrom(ip, bits),
		Lease:    ack.IPAddressLeaseTime(time.Hour),
		DNS:      addrsOf(ack.DNS()),
		NTP:      strings4(ack.NTPServers()),
		Hostname: ack.HostName(),
		Domain:   ack.DomainName(),
	}
	if r := ack.Router(); len(r) > 0 {
		l.Router, _ = addrOf(r[0])
	}
	if s := ack.DomainSearch(); s != nil {
		l.Search = s.Labels
	}
	return l, nil
}

var requested4 = dhcpv4.WithRequestedOptions(dhcpv4.OptionSubnetMask, dhcpv4.OptionRouter, dhcpv4.OptionDomainNameServer,
	dhcpv4.OptionNTPServers, dhcpv4.OptionHostName, dhcpv4.OptionDomainName, dhcpv4.OptionDNSDomainSearchList)

// DHCPv4 holds a lease on iface: discover and request, renew at T1, and
// start over when the lease runs out.
func (c Clients) DHCPv4(ctx context.Context, iface string, report func(*Lease4)) {
	lg := c.lg().With(log.F("iface", iface), log.F("client", "dhcpv4"))
	wait := retryMin
	for ctx.Err() == nil {
		cl, err := nclient4.New(iface, nclient4.WithTimeout(3*time.Second), nclient4.WithRetry(3))
		if err != nil {
			lg.Warn("netd: DHCPv4 client not started", log.F("error", err.Error()))
			if !sleep(ctx, wait) {
				return
			}
			wait = backoff(wait)
			continue
		}
		started := time.Now()
		raw, err := cl.Request(ctx, requested4)
		if err != nil {
			_ = cl.Close()
			lg.Warn("netd: no DHCPv4 lease", log.F("error", err.Error()), log.F("ms", time.Since(started).Milliseconds()))
			if !sleep(ctx, wait) {
				return
			}
			wait = backoff(wait)
			continue
		}
		wait = retryMin
		c.hold(ctx, lg, cl, raw, report)
		_ = cl.Close()
	}
}

// hold keeps one lease: report it, renew at T1 (again every 30 s up to the
// end), and report its loss.
func (c Clients) hold(ctx context.Context, lg log.Logger, cl *nclient4.Client, cur *nclient4.Lease, report func(*Lease4)) {
	for {
		l, err := lease4(cur.ACK)
		if err != nil {
			lg.Warn("netd: unusable DHCPv4 lease", log.F("error", err.Error()))
			return
		}
		lg.Debug("netd: DHCPv4 lease", log.F("address", l.Addr.String()), log.F("lease", l.Lease.String()))
		report(l)
		end := cur.CreationTime.Add(l.Lease)
		renewAt := cur.CreationTime.Add(cur.ACK.IPAddressRenewalTime(l.Lease / 2))
		if !sleep(ctx, time.Until(renewAt)) {
			return
		}
		for {
			next, err := cl.Renew(ctx, cur, requested4)
			if err == nil {
				cur = next
				break
			}
			lg.Warn("netd: DHCPv4 renewal failed", log.F("error", err.Error()))
			if time.Until(end) <= 0 {
				report(nil)
				return
			}
			if !sleep(ctx, min(30*time.Second, time.Until(end))) {
				return
			}
		}
	}
}

func lease6(msg *dhcpv6.Message) *Lease6 {
	l := &Lease6{DNS: addrsOf(msg.Options.DNS()), NTP: strings4(msg.Options.NTPServers())}
	if s := msg.Options.DomainSearchList(); s != nil {
		l.Search = s.Labels
	}
	if ia := msg.Options.OneIANA(); ia != nil {
		for _, a := range ia.Options.Addresses() {
			if ip, ok := addrOf(a.IPv6Addr); ok {
				l.Addr = netip.PrefixFrom(ip, 128)
				l.Valid, l.Preferred = a.ValidLifetime, a.PreferredLifetime
				break
			}
		}
	}
	return l
}

var requested6 = dhcpv6.WithRequestedOptions(dhcpv6.OptionDNSRecursiveNameServer, dhcpv6.OptionDomainSearchList, dhcpv6.OptionNTPServer)

// DHCPv6 asks for an address (stateful) or only the options (an
// information request), and asks again before the address or the
// information runs out.
func (c Clients) DHCPv6(ctx context.Context, iface string, stateful bool, report func(*Lease6)) {
	lg := c.lg().With(log.F("iface", iface), log.F("client", "dhcpv6"), log.F("stateful", stateful))
	wait := retryMin
	for ctx.Err() == nil {
		// The client binds the link-local address, which DAD may still be
		// testing.
		cl, err := nclient6.New(iface, nclient6.WithTimeout(3*time.Second), nclient6.WithRetry(3))
		if err != nil {
			lg.Debug("netd: DHCPv6 client not started yet", log.F("error", err.Error()))
			if !sleep(ctx, wait) {
				return
			}
			wait = backoff(wait)
			continue
		}
		var msg *dhcpv6.Message
		if stateful {
			msg, err = cl.RapidSolicit(ctx, requested6)
		} else {
			msg, err = c.inform(ctx, cl, iface)
		}
		_ = cl.Close()
		if err != nil {
			lg.Warn("netd: no DHCPv6 reply", log.F("error", err.Error()))
			if !sleep(ctx, wait) {
				return
			}
			wait = backoff(wait)
			continue
		}
		wait = retryMin
		l := lease6(msg)
		if stateful && !l.Addr.IsValid() {
			lg.Warn("netd: the DHCPv6 reply holds no address")
			if !sleep(ctx, wait) {
				return
			}
			continue
		}
		report(l)
		again := msg.Options.InformationRefreshTime(24 * time.Hour)
		if stateful {
			again = max(l.Preferred/2, 30*time.Second)
			if ia := msg.Options.OneIANA(); ia != nil && ia.T1 > 0 {
				again = ia.T1
			}
		}
		if !sleep(ctx, again) {
			return
		}
	}
}

func (c Clients) inform(ctx context.Context, cl *nclient6.Client, iface string) (*dhcpv6.Message, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	req, err := dhcpv6.NewMessage(requested6, dhcpv6.WithClientID(&dhcpv6.DUIDLL{HWType: 1, LinkLayerAddr: ifi.HardwareAddr}))
	if err != nil {
		return nil, err
	}
	req.MessageType = dhcpv6.MessageTypeInformationRequest
	return cl.SendAndRead(ctx, nclient6.AllDHCPRelayAgentsAndServers, req, nclient6.IsMessageType(dhcpv6.MessageTypeReply))
}

// RA reads router advertisements on iface (sending a solicitation first)
// and reports their flags, RDNSS and DNSSL. The kernel does the SLAAC
// addressing and the default route.
func (c Clients) RA(ctx context.Context, iface string, report func(*RAInfo)) {
	lg := c.lg().With(log.F("iface", iface), log.F("client", "ra"))
	wait := retryMin
	for ctx.Err() == nil {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			lg.Warn("netd: no interface for router advertisements", log.F("error", err.Error()))
			if !sleep(ctx, wait) {
				return
			}
			continue
		}
		conn, _, err := ndp.Listen(ifi, ndp.LinkLocal)
		if err != nil {
			lg.Debug("netd: router advertisements not read yet", log.F("error", err.Error()))
			if !sleep(ctx, wait) {
				return
			}
			wait = backoff(wait)
			continue
		}
		wait = retryMin
		c.readRA(ctx, lg, conn, ifi, report)
		_ = conn.Close()
	}
}

func (c Clients) readRA(ctx context.Context, lg log.Logger, conn *ndp.Conn, ifi *net.Interface, report func(*RAInfo)) {
	solicit := func() {
		rs := &ndp.RouterSolicitation{Options: []ndp.Option{&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: ifi.HardwareAddr}}}
		if err := conn.WriteTo(rs, nil, netip.IPv6LinkLocalAllRouters()); err != nil {
			lg.Debug("netd: router solicitation not sent", log.F("error", err.Error()))
		}
	}
	solicit()
	lastRA := time.Now()
	for ctx.Err() == nil {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		msg, _, from, err := conn.ReadFrom()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if time.Since(lastRA) > time.Minute {
					solicit()
					lastRA = time.Now()
				}
				continue
			}
			lg.Warn("netd: router advertisement read failed", log.F("error", err.Error()))
			return
		}
		ra, ok := msg.(*ndp.RouterAdvertisement)
		if !ok {
			continue
		}
		lastRA = time.Now()
		info := &RAInfo{Managed: ra.ManagedConfiguration, Other: ra.OtherConfiguration}
		for _, o := range ra.Options {
			switch o := o.(type) {
			case *ndp.RecursiveDNSServer:
				if o.Lifetime > 0 {
					info.RDNSS = append(info.RDNSS, o.Servers...)
				}
			case *ndp.DNSSearchList:
				if o.Lifetime > 0 {
					info.Search = append(info.Search, o.DomainNames...)
				}
			}
		}
		lg.Debug("netd: router advertisement", log.F("router", from.String()), log.F("rdnss", len(info.RDNSS)), log.F("managed", info.Managed), log.F("other", info.Other))
		report(info)
	}
}
