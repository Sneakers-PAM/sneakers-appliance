// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
)

// SYNSources reads the pcap file Options.Capture names and returns the
// source address of every TCP connection opened to target, in the order
// they left the guest: one per SYN without ACK. It is what the network the
// box sits on sees as the box's address for that connection.
func SYNSources(file string, target netip.AddrPort) ([]netip.Addr, error) {
	f, err := os.Open(file) // #nosec G304 -- the VM's own capture
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return nil, fmt.Errorf("pcap %s: %w", file, err)
	}
	var order binary.ByteOrder
	switch {
	case binary.LittleEndian.Uint32(hdr) == 0xa1b2c3d4:
		order = binary.LittleEndian
	case binary.BigEndian.Uint32(hdr) == 0xa1b2c3d4:
		order = binary.BigEndian
	default:
		return nil, fmt.Errorf("pcap %s: no pcap magic", file)
	}
	if link := order.Uint32(hdr[20:]); link != 1 {
		return nil, fmt.Errorf("pcap %s: link type %d, want Ethernet", file, link)
	}
	var out []netip.Addr
	rec := make([]byte, 16)
	for {
		if _, err := io.ReadFull(f, rec); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, fmt.Errorf("pcap %s: %w", file, err)
		}
		pkt := make([]byte, order.Uint32(rec[8:]))
		if _, err := io.ReadFull(f, pkt); err != nil {
			return nil, fmt.Errorf("pcap %s: %w", file, err)
		}
		if src, ok := synTo(pkt, target); ok {
			out = append(out, src)
		}
	}
}

// synTo reports the source of an Ethernet frame that opens a TCP
// connection to target.
func synTo(pkt []byte, target netip.AddrPort) (netip.Addr, bool) {
	if len(pkt) < 14+20 || binary.BigEndian.Uint16(pkt[12:]) != 0x0800 {
		return netip.Addr{}, false
	}
	ip := pkt[14:]
	ihl := int(ip[0]&0x0f) * 4
	if ip[0]>>4 != 4 || ip[9] != 6 || len(ip) < ihl+20 {
		return netip.Addr{}, false
	}
	src := netip.AddrFrom4([4]byte(ip[12:16]))
	dst := netip.AddrFrom4([4]byte(ip[16:20]))
	tcp := ip[ihl:]
	flags := tcp[13]
	if dst != target.Addr() || binary.BigEndian.Uint16(tcp[2:]) != target.Port() || flags&0x12 != 0x02 {
		return netip.Addr{}, false
	}
	return src, true
}
