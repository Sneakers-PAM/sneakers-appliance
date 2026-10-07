// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netns

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/server6"
	"github.com/mdlayher/ndp"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/timesync"
)

// RouterEnv carries a Router to the router helper.
const RouterEnv = "SNEAKERS_NETNS_ROUTER"

// Router is what the router helper serves on its interface: a DHCPv4
// server (insomniacslk/dhcp server4), a DHCPv6 server (server6), router
// advertisements (mdlayher/ndp), and DNS and SNTP responders. The
// interface's addresses are the test's to set.
type Router struct {
	Iface string
	// V4Lease is the address DHCPv4 hands out (192.0.2.100/24); empty
	// runs no DHCPv4 server.
	V4Lease, V4Router string
	// RAPrefix is advertised for SLAAC unless Managed is set; empty sends
	// no router advertisements.
	RAPrefix       string
	RDNSS          string
	Managed, Other bool
	// V6Lease is the address DHCPv6 hands out; with RAPrefix it only runs
	// the information reply when empty.
	V6Lease string
	// DNS and NTP are handed out by both DHCP servers.
	DNS, NTP string
	// Listen are the addresses the DNS and SNTP responders listen on.
	Listen []string
}

// Env is the helper environment for r.
func (r Router) Env() string {
	b, _ := json.Marshal(r)
	return RouterEnv + "=" + string(b)
}

// RouterHelper is the router helper: add it to RunHelpers as "router".
func RouterHelper() error {
	var r Router
	if err := json.Unmarshal([]byte(os.Getenv(RouterEnv)), &r); err != nil {
		return err
	}
	errs := make(chan error, 8)
	for _, a := range r.Listen {
		ap := netip.MustParseAddr(a)
		go func() { errs <- serveDNS(ap) }()
		go func() { errs <- serveNTP(ap) }()
	}
	if r.V4Lease != "" {
		go func() { errs <- serveDHCPv4(r) }()
	}
	if r.RAPrefix != "" {
		go func() { errs <- serveDHCPv6(r) }()
		go func() { errs <- sendRA(r) }()
	}
	fmt.Println("router ready")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
		return nil
	case err := <-errs:
		return err
	}
}

func ips(s string) []net.IP {
	if s == "" {
		return nil
	}
	return []net.IP{net.ParseIP(s)}
}

func serveDHCPv4(r Router) error {
	lease := netip.MustParsePrefix(r.V4Lease)
	mask := net.CIDRMask(lease.Bits(), 32)
	handler := func(conn net.PacketConn, _ net.Addr, m *dhcpv4.DHCPv4) {
		var mt dhcpv4.MessageType
		switch m.MessageType() {
		case dhcpv4.MessageTypeDiscover:
			mt = dhcpv4.MessageTypeOffer
		case dhcpv4.MessageTypeRequest:
			mt = dhcpv4.MessageTypeAck
		default:
			return
		}
		router := net.ParseIP(r.V4Router)
		mods := []dhcpv4.Modifier{
			dhcpv4.WithMessageType(mt), dhcpv4.WithYourIP(net.IP(lease.Addr().AsSlice())), dhcpv4.WithNetmask(mask),
			dhcpv4.WithLeaseTime(3600), dhcpv4.WithServerIP(router),
			dhcpv4.WithOption(dhcpv4.OptServerIdentifier(router)), dhcpv4.WithOption(dhcpv4.OptRouter(router)),
			dhcpv4.WithOption(dhcpv4.OptHostName("box1")), dhcpv4.WithOption(dhcpv4.OptDomainName("sneakers.example.org")),
		}
		if r.DNS != "" {
			mods = append(mods, dhcpv4.WithOption(dhcpv4.OptDNS(ips(r.DNS)...)))
		}
		if r.NTP != "" {
			mods = append(mods, dhcpv4.WithOption(dhcpv4.OptNTPServers(ips(r.NTP)...)))
		}
		reply, err := dhcpv4.NewReplyFromRequest(m, mods...)
		if err != nil {
			return
		}
		_, _ = conn.WriteTo(reply.ToBytes(), &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpv4.ClientPort})
	}
	srv, err := server4.NewServer(r.Iface, &net.UDPAddr{IP: net.IPv4zero, Port: dhcpv4.ServerPort}, handler)
	if err != nil {
		return err
	}
	return srv.Serve()
}

func serveDHCPv6(r Router) error {
	ifi, err := net.InterfaceByName(r.Iface)
	if err != nil {
		return err
	}
	duid := &dhcpv6.DUIDLL{HWType: 1, LinkLayerAddr: ifi.HardwareAddr}
	handler := func(conn net.PacketConn, peer net.Addr, m dhcpv6.DHCPv6) {
		msg, err := m.GetInnerMessage()
		if err != nil {
			return
		}
		mods := []dhcpv6.Modifier{dhcpv6.WithServerID(duid)}
		if r.DNS != "" {
			mods = append(mods, dhcpv6.WithDNS(ips(r.DNS)...))
		}
		if r.NTP != "" {
			addr := dhcpv6.NTPSuboptionSrvAddr(net.ParseIP(r.NTP))
			mods = append(mods, dhcpv6.WithOption(&dhcpv6.OptNTPServer{Suboptions: dhcpv6.Options{&addr}}))
		}
		stateful := msg.MessageType == dhcpv6.MessageTypeSolicit || msg.MessageType == dhcpv6.MessageTypeRequest
		if stateful {
			if r.V6Lease == "" {
				return
			}
			var iaid [4]byte
			if ia := msg.Options.OneIANA(); ia != nil {
				iaid = ia.IaId
			}
			mods = append(mods, dhcpv6.WithOption(&dhcpv6.OptIANA{IaId: iaid, T1: 30 * time.Minute, T2: 45 * time.Minute,
				Options: dhcpv6.IdentityOptions{Options: dhcpv6.Options{&dhcpv6.OptIAAddress{
					IPv6Addr: net.ParseIP(r.V6Lease), PreferredLifetime: time.Hour, ValidLifetime: 2 * time.Hour}}}}))
		}
		var reply *dhcpv6.Message
		switch {
		case msg.MessageType == dhcpv6.MessageTypeSolicit && msg.GetOneOption(dhcpv6.OptionRapidCommit) == nil:
			reply, err = dhcpv6.NewAdvertiseFromSolicit(msg, mods...)
		default:
			reply, err = dhcpv6.NewReplyFromMessage(msg, mods...)
		}
		if err != nil {
			return
		}
		_, _ = conn.WriteTo(reply.ToBytes(), peer)
	}
	srv, err := server6.NewServer(r.Iface, nil, handler)
	if err != nil {
		return err
	}
	return srv.Serve()
}

func sendRA(r Router) error {
	ifi, err := net.InterfaceByName(r.Iface)
	if err != nil {
		return err
	}
	var conn *ndp.Conn
	for i := 0; ; i++ {
		conn, _, err = ndp.Listen(ifi, ndp.LinkLocal)
		if err == nil {
			break
		}
		if i > 50 {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	prefix := netip.MustParsePrefix(r.RAPrefix)
	opts := []ndp.Option{
		&ndp.PrefixInformation{PrefixLength: uint8(prefix.Bits()), OnLink: true, AutonomousAddressConfiguration: !r.Managed, // #nosec G115 -- 0 to 128
			ValidLifetime: 2 * time.Hour, PreferredLifetime: time.Hour, Prefix: prefix.Addr()},
		&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: ifi.HardwareAddr},
	}
	if r.RDNSS != "" {
		opts = append(opts, &ndp.RecursiveDNSServer{Lifetime: time.Hour, Servers: []netip.Addr{netip.MustParseAddr(r.RDNSS)}},
			&ndp.DNSSearchList{Lifetime: time.Hour, DomainNames: []string{"sneakers.example.org"}})
	}
	ra := &ndp.RouterAdvertisement{CurrentHopLimit: 64, ManagedConfiguration: r.Managed, OtherConfiguration: r.Other || r.Managed,
		RouterLifetime: 30 * time.Minute, Options: opts}
	for {
		if err := conn.WriteTo(ra, nil, netip.IPv6LinkLocalAllNodes()); err != nil {
			return err
		}
		time.Sleep(time.Second)
	}
}

// serveDNS answers every A and AAAA question with one documentation
// address.
func serveDNS(at netip.Addr) error {
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(at, 53)))
	if err != nil {
		return err
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return err
		}
		var p dnsmessage.Parser
		h, err := p.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true})
		_ = b.StartQuestions()
		_ = b.Question(q)
		_ = b.StartAnswers()
		rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}
		switch q.Type {
		case dnsmessage.TypeA:
			_ = b.AResource(rh, dnsmessage.AResource{A: [4]byte{192, 0, 2, 123}})
		case dnsmessage.TypeAAAA:
			_ = b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::123").As16()})
		}
		out, err := b.Finish()
		if err != nil {
			continue
		}
		_, _ = pc.WriteToUDPAddrPort(out, from)
	}
}

// serveNTP answers SNTP requests with the host's clock, stratum 2.
func serveNTP(at netip.Addr) error {
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(at, timesync.Port)))
	if err != nil {
		return err
	}
	buf := make([]byte, 512)
	for {
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		req, err := timesync.ParseHeader(buf[:n])
		if err != nil {
			continue
		}
		now := timesync.TimestampFromTime(time.Now())
		reply := timesync.Header{Version: 4, Mode: timesync.ModeServer, Stratum: 2, RootDelay: 0x100, RootDispersion: 0x100,
			ReferenceID: [4]byte{'L', 'A', 'B', 0}, Reference: now, Origin: req.Transmit, Receive: now, Transmit: now}
		_, _ = pc.WriteToUDPAddrPort(reply.Marshal(), from)
	}
}
