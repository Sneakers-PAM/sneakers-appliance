// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0
// Copyright The CryptOS Authors.

package netlink

import (
	"encoding/binary"
	"net/netip"
)

// rtnetlink ABI constants (stable Linux kernel values), defined here so the
// builders and parsers test on any host.
const (
	rtmNewLink  = 16 // RTM_NEWLINK
	rtmNewAddr  = 20 // RTM_NEWADDR
	rtmDelAddr  = 21 // RTM_DELADDR
	rtmGetAddr  = 22 // RTM_GETADDR
	rtmNewRoute = 24 // RTM_NEWROUTE
	rtmDelRoute = 25 // RTM_DELROUTE
	rtmGetRoute = 26 // RTM_GETROUTE
	rtmNewNeigh = 28 // RTM_NEWNEIGH
	rtmGetNeigh = 30 // RTM_GETNEIGH

	nlmFRequest = 0x001 // NLM_F_REQUEST
	nlmFAck     = 0x004 // NLM_F_ACK
	nlmFDump    = 0x300 // NLM_F_ROOT|NLM_F_MATCH
	nlmFReplace = 0x100 // NLM_F_REPLACE
	nlmFCreate  = 0x400 // NLM_F_CREATE

	nlmsgError = 0x2 // NLMSG_ERROR
	nlmsgDone  = 0x3 // NLMSG_DONE

	iffUp = 0x1 // IFF_UP

	ifaAddress   = 1 // IFA_ADDRESS
	ifaLocal     = 2 // IFA_LOCAL
	ifaCacheinfo = 6 // IFA_CACHEINFO
	ifaFlags     = 8 // IFA_FLAGS

	rtaDst      = 1  // RTA_DST
	rtaOif      = 4  // RTA_OIF
	rtaGateway  = 5  // RTA_GATEWAY
	rtaPriority = 6  // RTA_PRIORITY
	rtaTable    = 15 // RTA_TABLE

	ndaDst = 1 // NDA_DST

	rtnUnicast      = 1   // RTN_UNICAST
	rtScopeUniverse = 0   // RT_SCOPE_UNIVERSE
	rtScopeLink     = 253 // RT_SCOPE_LINK
	rtTableMain     = 254 // RT_TABLE_MAIN

	afUnspec = 0  // AF_UNSPEC
	afInet   = 2  // AF_INET
	afInet6  = 10 // AF_INET6

	nlmsghdrLen  = 16 // sizeof(struct nlmsghdr)
	ifinfomsgLen = 16 // sizeof(struct ifinfomsg)
	ifaddrmsgLen = 8  // sizeof(struct ifaddrmsg)
	rtmsgLen     = 12 // sizeof(struct rtmsg)
	ndmsgLen     = 12 // sizeof(struct ndmsg)
	rtattrHdrLen = 4  // sizeof(struct rtattr)
)

// Address flags (IFA_F_*), as Addr.Flags carries them.
const (
	FlagTemporary  = 0x01
	FlagOptimistic = 0x04
	FlagDADFailed  = 0x08
	FlagDeprecated = 0x20
	FlagTentative  = 0x40
	FlagPermanent  = 0x80
)

// Route protocols (RTPROT_*): who installed a route.
const (
	ProtoKernel = 2
	ProtoBoot   = 3
	ProtoStatic = 4
	ProtoRA     = 9
	ProtoDHCP   = 16
)

// Neighbour states (NUD_*).
const (
	NUDIncomplete = 0x01
	NUDReachable  = 0x02
	NUDStale      = 0x04
	NUDDelay      = 0x08
	NUDProbe      = 0x10
	NUDFailed     = 0x20
	NUDNoARP      = 0x40
	NUDPermanent  = 0x80
)

// Forever is the lifetime of an address that never expires.
const Forever = 0xffffffff

// native is the host byte order; netlink uses host endianness on the wire.
var native = binary.NativeEndian

// rtaAlign rounds n up to the 4-byte rtattr and netlink alignment.
func rtaAlign(n int) int { return (n + 3) &^ 3 }

// attr encodes one rtattr: a 4-byte header (len, type), then data padded to
// the alignment. The length counts header and data, not the padding.
func attr(typ uint16, data []byte) []byte {
	l := rtattrHdrLen + len(data)
	buf := make([]byte, rtaAlign(l))
	native.PutUint16(buf[0:2], uint16(l)) // #nosec G115 -- an attribute is far below 64 KiB
	native.PutUint16(buf[2:4], typ)
	copy(buf[4:], data)
	return buf
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	native.PutUint32(b, v)
	return b
}

// frame prepends an nlmsghdr to body.
func frame(msgType, flags uint16, seq uint32, body []byte) []byte {
	buf := make([]byte, nlmsghdrLen+len(body))
	native.PutUint32(buf[0:4], uint32(len(buf))) // #nosec G115 -- a request is far below 4 GiB
	native.PutUint16(buf[4:6], msgType)
	native.PutUint16(buf[6:8], flags)
	native.PutUint32(buf[8:12], seq)
	copy(buf[nlmsghdrLen:], body)
	return buf
}

func family(a netip.Addr) byte {
	if a.Is4() {
		return afInet
	}
	return afInet6
}

func addrBytes(a netip.Addr) []byte {
	if a.Is4() {
		b := a.As4()
		return b[:]
	}
	b := a.As16()
	return b[:]
}

func index32(ifIndex int) uint32 { return uint32(int32(ifIndex)) } // #nosec G115 -- a kernel interface index fits an int32

// buildLinkUpRequest sets IFF_UP on ifIndex.
func buildLinkUpRequest(seq uint32, ifIndex int) []byte {
	body := make([]byte, ifinfomsgLen)
	body[0] = afUnspec
	native.PutUint32(body[4:8], index32(ifIndex))
	native.PutUint32(body[8:12], iffUp)
	native.PutUint32(body[12:16], iffUp)
	return frame(rtmNewLink, nlmFRequest|nlmFAck, seq, body)
}

// buildAddrRequest adds (or replaces) p on ifIndex. valid and preferred are
// lifetimes in seconds; Forever for both leaves out IFA_CACHEINFO, which
// makes the address permanent.
func buildAddrRequest(seq uint32, ifIndex int, p netip.Prefix, valid, preferred uint32) []byte {
	a := p.Addr()
	body := make([]byte, ifaddrmsgLen)
	body[0] = family(a)
	body[1] = byte(p.Bits()) // #nosec G115 -- a prefix length is 0 to 128
	body[3] = rtScopeUniverse
	native.PutUint32(body[4:8], index32(ifIndex))
	body = append(body, attr(ifaLocal, addrBytes(a))...)
	body = append(body, attr(ifaAddress, addrBytes(a))...)
	if valid != Forever || preferred != Forever {
		ci := make([]byte, 16)
		native.PutUint32(ci[0:4], preferred)
		native.PutUint32(ci[4:8], valid)
		body = append(body, attr(ifaCacheinfo, ci)...)
	}
	return frame(rtmNewAddr, nlmFRequest|nlmFAck|nlmFCreate|nlmFReplace, seq, body)
}

// buildAddrDelRequest removes p from ifIndex.
func buildAddrDelRequest(seq uint32, ifIndex int, p netip.Prefix) []byte {
	a := p.Addr()
	body := make([]byte, ifaddrmsgLen)
	body[0] = family(a)
	body[1] = byte(p.Bits()) // #nosec G115 -- as above
	body[3] = rtScopeUniverse
	native.PutUint32(body[4:8], index32(ifIndex))
	body = append(body, attr(ifaLocal, addrBytes(a))...)
	body = append(body, attr(ifaAddress, addrBytes(a))...)
	return frame(rtmDelAddr, nlmFRequest|nlmFAck, seq, body)
}

// buildDefaultRouteRequest adds or replaces the default route of gw's
// family via gw out of ifIndex at metric. NLM_F_REPLACE keeps netd
// authoritative over a route the kernel's own autoconfiguration left.
func buildDefaultRouteRequest(seq uint32, ifIndex int, gw netip.Addr, metric uint32, proto byte) []byte {
	body := make([]byte, rtmsgLen)
	body[0] = family(gw)
	body[4] = rtTableMain
	body[5] = proto
	body[6] = rtScopeUniverse
	body[7] = rtnUnicast
	body = append(body, attr(rtaGateway, addrBytes(gw))...)
	body = append(body, attr(rtaOif, u32(index32(ifIndex)))...)
	body = append(body, attr(rtaPriority, u32(metric))...)
	return frame(rtmNewRoute, nlmFRequest|nlmFAck|nlmFCreate|nlmFReplace, seq, body)
}

// buildDefaultRouteDelRequest removes the default route of fam out of
// ifIndex at metric.
func buildDefaultRouteDelRequest(seq uint32, fam byte, ifIndex int, metric uint32) []byte {
	body := make([]byte, rtmsgLen)
	body[0] = fam
	body[4] = rtTableMain
	body[6] = rtScopeUniverse
	body[7] = rtnUnicast
	body = append(body, attr(rtaOif, u32(index32(ifIndex)))...)
	body = append(body, attr(rtaPriority, u32(metric))...)
	return frame(rtmDelRoute, nlmFRequest|nlmFAck, seq, body)
}

func buildDumpRequest(seq uint32, msgType uint16, bodyLen int) []byte {
	return frame(msgType, nlmFRequest|nlmFDump, seq, make([]byte, bodyLen))
}

// Addr is one address the kernel holds.
type Addr struct {
	Index  int
	Prefix netip.Prefix
	// Flags are the IFA_F_* flags (IFA_FLAGS when the kernel sends it).
	Flags uint32
	Scope byte
	// Valid and Preferred are the remaining lifetimes in seconds, Forever
	// for a permanent address.
	Valid, Preferred uint32
}

// Tentative reports whether DAD is still running on the address.
func (a Addr) Tentative() bool { return a.Flags&FlagTentative != 0 }

// DADFailed reports whether another host holds the address.
func (a Addr) DADFailed() bool { return a.Flags&FlagDADFailed != 0 }

// walkAttrs calls fn for each rtattr in b.
func walkAttrs(b []byte, fn func(typ uint16, data []byte)) {
	for len(b) >= rtattrHdrLen {
		l := int(native.Uint16(b[0:2]))
		if l < rtattrHdrLen || l > len(b) {
			return
		}
		fn(native.Uint16(b[2:4]), b[rtattrHdrLen:l])
		if rtaAlign(l) > len(b) {
			return
		}
		b = b[rtaAlign(l):]
	}
}

func parseIP(data []byte) (netip.Addr, bool) {
	switch len(data) {
	case 4, 16:
		a, _ := netip.AddrFromSlice(data)
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

// messages yields the payload of every message of msgType.
func messages(msgs [][]byte, msgType uint16, minLen int, fn func(body []byte)) {
	for _, m := range msgs {
		if len(m) < nlmsghdrLen+minLen || native.Uint16(m[4:6]) != msgType {
			continue
		}
		l := int(native.Uint32(m[0:4]))
		if l > len(m) || l < nlmsghdrLen+minLen {
			continue
		}
		fn(m[nlmsghdrLen:l])
	}
}

// parseAddrMessages reads an RTM_GETADDR dump (or RTM_NEWADDR notices).
func parseAddrMessages(msgs [][]byte) []Addr {
	var out []Addr
	messages(msgs, rtmNewAddr, ifaddrmsgLen, func(b []byte) {
		a := Addr{Index: int(int32(native.Uint32(b[4:8]))), Flags: uint32(b[2]), Scope: b[3], Valid: Forever, Preferred: Forever} // #nosec G115 -- the kernel's int32 index
		bits := int(b[1])
		var local, addr netip.Addr
		walkAttrs(b[ifaddrmsgLen:], func(typ uint16, data []byte) {
			switch typ {
			case ifaLocal:
				local, _ = parseIP(data)
			case ifaAddress:
				addr, _ = parseIP(data)
			case ifaFlags:
				if len(data) == 4 {
					a.Flags = native.Uint32(data)
				}
			case ifaCacheinfo:
				if len(data) >= 8 {
					a.Preferred, a.Valid = native.Uint32(data[0:4]), native.Uint32(data[4:8])
				}
			}
		})
		ip := local
		if !ip.IsValid() {
			ip = addr
		}
		if !ip.IsValid() {
			return
		}
		a.Prefix = netip.PrefixFrom(ip, bits)
		out = append(out, a)
	})
	return out
}

// Route is one route the kernel holds.
type Route struct {
	Dst      netip.Prefix
	Gateway  netip.Addr
	Oif      int
	Table    uint32
	Protocol byte
	Metric   uint32
}

// Default reports whether r is a default route.
func (r Route) Default() bool { return r.Dst.Bits() == 0 }

// parseRouteMessages reads an RTM_GETROUTE dump.
func parseRouteMessages(msgs [][]byte) []Route {
	var out []Route
	messages(msgs, rtmNewRoute, rtmsgLen, func(b []byte) {
		fam, dstLen := b[0], int(b[1])
		r := Route{Table: uint32(b[4]), Protocol: b[5]}
		var dst netip.Addr
		walkAttrs(b[rtmsgLen:], func(typ uint16, data []byte) {
			switch typ {
			case rtaDst:
				dst, _ = parseIP(data)
			case rtaGateway:
				r.Gateway, _ = parseIP(data)
			case rtaOif:
				if len(data) == 4 {
					r.Oif = int(int32(native.Uint32(data))) // #nosec G115 -- the kernel's int32 index
				}
			case rtaPriority:
				if len(data) == 4 {
					r.Metric = native.Uint32(data)
				}
			case rtaTable:
				if len(data) == 4 {
					r.Table = native.Uint32(data)
				}
			}
		})
		if !dst.IsValid() {
			dst = netip.IPv4Unspecified()
			if fam == afInet6 {
				dst = netip.IPv6Unspecified()
			}
		}
		r.Dst = netip.PrefixFrom(dst, dstLen)
		out = append(out, r)
	})
	return out
}

// Neigh is one neighbour (ARP or NDP) entry.
type Neigh struct {
	Index int
	Addr  netip.Addr
	State uint16
}

// Usable reports whether the neighbour answered: its link-layer address
// is known.
func (n Neigh) Usable() bool {
	return n.State&(NUDReachable|NUDStale|NUDDelay|NUDProbe|NUDPermanent|NUDNoARP) != 0
}

// parseNeighMessages reads an RTM_GETNEIGH dump.
func parseNeighMessages(msgs [][]byte) []Neigh {
	var out []Neigh
	messages(msgs, rtmNewNeigh, ndmsgLen, func(b []byte) {
		n := Neigh{Index: int(int32(native.Uint32(b[4:8]))), State: native.Uint16(b[8:10])} // #nosec G115 -- the kernel's int32 index
		walkAttrs(b[ndmsgLen:], func(typ uint16, data []byte) {
			if typ == ndaDst {
				n.Addr, _ = parseIP(data)
			}
		})
		if n.Addr.IsValid() {
			out = append(out, n)
		}
	})
	return out
}

// parseAck reads the kernel's reply to an NLM_F_ACK request: the errno (0
// on success) and whether it was an ACK at all.
func parseAck(resp []byte) (errno int32, ok bool) {
	if len(resp) < nlmsghdrLen+4 || native.Uint16(resp[4:6]) != nlmsgError {
		return 0, false
	}
	return int32(native.Uint32(resp[nlmsghdrLen : nlmsghdrLen+4])), true // #nosec G115 -- the kernel's signed errno
}
