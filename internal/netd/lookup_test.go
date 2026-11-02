// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/netd"
)

// answer builds the reply to a query for the records in names.
func answer(t *testing.T, q []byte, names map[string][]netip.Addr) []byte {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		t.Error(err)
		return nil
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		t.Errorf("questions %v %v", qs, err)
		return nil
	}
	recs, known := names[qs[0].Name.String()]
	rc := dnsmessage.RCodeSuccess
	if !known {
		rc = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RCode: rc})
	_ = b.StartQuestions()
	_ = b.Question(qs[0])
	_ = b.StartAnswers()
	for _, a := range recs {
		rh := dnsmessage.ResourceHeader{Name: qs[0].Name, Class: dnsmessage.ClassINET, TTL: 60}
		switch {
		case a.Is4() && qs[0].Type == dnsmessage.TypeA:
			_ = b.AResource(rh, dnsmessage.AResource{A: a.As4()})
		case a.Is6() && qs[0].Type == dnsmessage.TypeAAAA:
			_ = b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: a.As16()})
		}
	}
	out, err := b.Finish()
	if err != nil {
		t.Error(err)
	}
	return out
}

// tcpDNS answers DNS over TCP only, as the image suite's server behind
// QEMU's guestfwd does.
func tcpDNS(t *testing.T, names map[string][]netip.Addr) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				for {
					var n [2]byte
					if _, err := io.ReadFull(c, n[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(n[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					r := answer(t, q, names)
					_, _ = c.Write(binary.BigEndian.AppendUint16(nil, uint16(len(r)))) // #nosec G115 -- a small reply
					_, _ = c.Write(r)
				}
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// udpDNS answers over UDP on the same port number as the TCP one.
func udpDNS(t *testing.T, at netip.AddrPort, names map[string][]netip.Addr) {
	t.Helper()
	pc, err := net.ListenPacket("udp", at.String())
	if err != nil {
		t.Skipf("no UDP on %s: %v", at, err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(answer(t, buf[:n], names), from)
		}
	}()
}

var zone = map[string][]netip.Addr{
	"appliance.example.org.": {netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")},
	"v4only.example.org.":    {netip.MustParseAddr("192.0.2.77")},
	"empty.example.org.":     {},
}

func TestLookupReadsBothFamiliesOverUDP(t *testing.T) {
	srv := tcpDNS(t, nil)
	udpDNS(t, srv, zone)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := netd.Lookup(ctx, srv, "appliance.example.org")
	if err != nil || len(got) != 2 || got[0].String() != "192.0.2.10" || got[1].String() != "2001:db8::10" {
		t.Fatalf("%v %v", got, err)
	}
}

// Without UDP (a network that drops it, or the image suite's forward) the
// lookup goes over TCP.
func TestLookupFallsBackToTCP(t *testing.T) {
	srv := tcpDNS(t, zone)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := netd.Lookup(ctx, srv, "v4only.example.org")
	if err != nil || len(got) != 1 || got[0].String() != "192.0.2.77" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := netd.Lookup(ctx, srv, "nothere.example.org"); !errors.Is(err, netd.ErrNoSuchName) {
		t.Fatalf("want ErrNoSuchName, got %v", err)
	}
	if _, err := netd.Lookup(ctx, srv, "empty.example.org"); !errors.Is(err, netd.ErrNoSuchName) {
		t.Fatalf("a name with no address records: want ErrNoSuchName, got %v", err)
	}
}

func TestLookupSaysWhenTheServerDoesntAnswer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	at := netip.MustParseAddrPort(ln.Addr().String())
	_ = ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := netd.Lookup(ctx, at, "appliance.example.org"); err == nil || errors.Is(err, netd.ErrNoSuchName) {
		t.Fatalf("want a no-answer error, got %v", err)
	}
}
