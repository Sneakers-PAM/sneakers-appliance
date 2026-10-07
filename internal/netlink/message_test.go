// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netlink

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestAttrPadsToFourBytes(t *testing.T) {
	got := attr(7, []byte{1, 2, 3, 4, 5})
	want := make([]byte, 12)
	native.PutUint16(want[0:2], 9)
	native.PutUint16(want[2:4], 7)
	copy(want[4:], []byte{1, 2, 3, 4, 5})
	if !bytes.Equal(got, want) {
		t.Fatalf("attr = %x, want %x", got, want)
	}
}

func TestLinkUpRequest(t *testing.T) {
	m := buildLinkUpRequest(3, 5)
	if len(m) != nlmsghdrLen+ifinfomsgLen || native.Uint16(m[4:6]) != rtmNewLink || native.Uint32(m[8:12]) != 3 {
		t.Fatalf("header %x", m[:16])
	}
	if native.Uint32(m[20:24]) != 5 || native.Uint32(m[24:28]) != iffUp || native.Uint32(m[28:32]) != iffUp {
		t.Fatalf("body %x", m[16:])
	}
}

// An address request is an RTM_NEWADDR message, so the dump parser reads
// back what it asked for: the family, the prefix, the index and the
// lifetimes.
func TestAddrRequestRoundTrips(t *testing.T) {
	for _, c := range []struct {
		p                netip.Prefix
		valid, preferred uint32
	}{
		{netip.MustParsePrefix("192.0.2.10/24"), Forever, Forever},
		{netip.MustParsePrefix("2001:db8::10/64"), Forever, Forever},
		{netip.MustParsePrefix("2001:db8:1::7/128"), 7200, 3600},
	} {
		m := buildAddrRequest(1, 4, c.p, c.valid, c.preferred)
		got := parseAddrMessages([][]byte{m})
		if len(got) != 1 {
			t.Fatalf("%s: parsed %d addresses", c.p, len(got))
		}
		a := got[0]
		if a.Prefix != c.p || a.Index != 4 || a.Valid != c.valid || a.Preferred != c.preferred {
			t.Fatalf("%s: parsed %+v", c.p, a)
		}
		if f := m[nlmsghdrLen]; (c.p.Addr().Is4() && f != afInet) || (c.p.Addr().Is6() && f != afInet6) {
			t.Fatalf("%s: family %d", c.p, f)
		}
	}
}

func TestAddrFlagsPreferTheFlagsAttribute(t *testing.T) {
	m := buildAddrRequest(1, 2, netip.MustParsePrefix("2001:db8::5/64"), Forever, Forever)
	m = append(m, attr(ifaFlags, u32(FlagTentative|0x100))...)
	native.PutUint32(m[0:4], uint32(len(m)))
	a := parseAddrMessages([][]byte{m})[0]
	if !a.Tentative() || a.DADFailed() || a.Flags&0x100 == 0 {
		t.Fatalf("flags %#x", a.Flags)
	}
}

func TestDefaultRouteRequestRoundTrips(t *testing.T) {
	for _, gw := range []string{"192.0.2.1", "fe80::1"} {
		m := buildDefaultRouteRequest(9, 3, netip.MustParseAddr(gw), 100, ProtoDHCP)
		if native.Uint16(m[6:8])&nlmFReplace == 0 {
			t.Fatalf("%s: no NLM_F_REPLACE", gw)
		}
		r := parseRouteMessages([][]byte{m})
		if len(r) != 1 || !r[0].Default() || r[0].Gateway.String() != gw || r[0].Oif != 3 || r[0].Metric != 100 || r[0].Protocol != ProtoDHCP || r[0].Table != rtTableMain {
			t.Fatalf("%s: parsed %+v", gw, r)
		}
	}
}

func TestDefaultRouteDelRequest(t *testing.T) {
	m := buildDefaultRouteDelRequest(2, afInet6, 3, 100)
	if native.Uint16(m[4:6]) != rtmDelRoute || m[nlmsghdrLen] != afInet6 {
		t.Fatalf("header %x", m[:20])
	}
}

func TestParseNeighbours(t *testing.T) {
	body := make([]byte, ndmsgLen)
	body[0] = afInet
	native.PutUint32(body[4:8], 3)
	native.PutUint16(body[8:10], NUDReachable)
	a := netip.MustParseAddr("192.0.2.1").As4()
	body = append(body, attr(ndaDst, a[:])...)
	failed := append([]byte(nil), body...)
	native.PutUint16(failed[8:10], NUDFailed)
	got := parseNeighMessages([][]byte{frame(rtmNewNeigh, 0, 1, body), frame(rtmNewNeigh, 0, 1, failed), frame(nlmsgDone, 0, 1, nil)})
	if len(got) != 2 || !got[0].Usable() || got[1].Usable() || got[0].Addr.String() != "192.0.2.1" || got[0].Index != 3 {
		t.Fatalf("parsed %+v", got)
	}
}

func TestParseAck(t *testing.T) {
	ok := frame(nlmsgError, 0, 1, u32(0))
	if e, isAck := parseAck(ok); !isAck || e != 0 {
		t.Fatalf("ack: %d %v", e, isAck)
	}
	bad := frame(nlmsgError, 0, 1, u32(uint32(0xffffffef))) // -17, EEXIST
	if e, isAck := parseAck(bad); !isAck || e != -17 {
		t.Fatalf("error: %d %v", e, isAck)
	}
	if _, isAck := parseAck(frame(nlmsgDone, 0, 1, nil)); isAck {
		t.Fatal("NLMSG_DONE read as an ack")
	}
}

func TestTruncatedMessagesAreSkipped(t *testing.T) {
	m := buildAddrRequest(1, 4, netip.MustParsePrefix("192.0.2.10/24"), Forever, Forever)
	if got := parseAddrMessages([][]byte{m[:nlmsghdrLen+4]}); len(got) != 0 {
		t.Fatalf("parsed %+v from a truncated message", got)
	}
	native.PutUint32(m[0:4], uint32(len(m)+40))
	if got := parseAddrMessages([][]byte{m}); len(got) != 0 {
		t.Fatalf("parsed %+v from a message longer than its buffer", got)
	}
}
