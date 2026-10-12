// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// frame is one Ethernet frame carrying an IPv4 TCP segment.
func frame(src, dst netip.Addr, sport, dport uint16, flags byte) []byte {
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 6
	binary.BigEndian.PutUint16(ip[2:], 40)
	s, d := src.As4(), dst.As4()
	copy(ip[12:16], s[:])
	copy(ip[16:20], d[:])
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	tcp[12] = 5 << 4
	tcp[13] = flags
	return slices.Concat(eth, ip, tcp)
}

// pcapFile writes frames as a pcap file in the host's byte order, as
// QEMU's filter-dump does.
func pcapFile(t *testing.T, order binary.ByteOrder, frames ...[]byte) string {
	t.Helper()
	var b bytes.Buffer
	hdr := make([]byte, 24)
	order.PutUint32(hdr[0:], 0xa1b2c3d4)
	order.PutUint16(hdr[4:], 2)
	order.PutUint16(hdr[6:], 4)
	order.PutUint32(hdr[16:], 65535)
	order.PutUint32(hdr[20:], 1)
	b.Write(hdr)
	for _, f := range frames {
		rec := make([]byte, 16)
		order.PutUint32(rec[8:], uint32(len(f)))  // #nosec G115 -- test frames are small
		order.PutUint32(rec[12:], uint32(len(f))) // #nosec G115 -- as above
		b.Write(rec)
		b.Write(f)
	}
	p := filepath.Join(t.TempDir(), "n0.pcap")
	if err := os.WriteFile(p, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSYNSourcesNamesTheSourceOfEachConnectionToTheTarget(t *testing.T) {
	box := netip.MustParseAddr("10.0.2.15")              // scrub:allow=private-ip -- QEMU's user network and the k0s pod range
	pod := netip.MustParseAddr("10.244.0.7")             // scrub:allow=private-ip -- QEMU's user network and the k0s pod range
	target := netip.MustParseAddrPort("10.0.2.100:7777") // scrub:allow=private-ip -- QEMU's user network and the k0s pod range
	other := netip.MustParseAddr("10.0.2.2")             // scrub:allow=private-ip -- QEMU's user network and the k0s pod range
	const syn, ack = 0x02, 0x10
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		p := pcapFile(t, order,
			frame(box, other, 40000, 7777, syn),             // another destination
			frame(box, target.Addr(), 40001, 22, syn),       // another port
			frame(box, target.Addr(), 40002, 7777, syn|ack), // not a new connection
			frame(pod, target.Addr(), 40003, 7777, syn),     // left unmasqueraded
			frame(box, target.Addr(), 40004, 7777, syn),     // masqueraded
			frame(target.Addr(), box, 7777, 40004, syn|ack), // the answer
			frame(box, target.Addr(), 40004, 7777, ack),     // the rest of it
		)
		got, err := SYNSources(p, target)
		if err != nil {
			t.Fatal(err)
		}
		if want := []netip.Addr{pod, box}; !slices.Equal(got, want) {
			t.Fatalf("%v: SYNSources = %v, want %v", order, got, want)
		}
	}
}

func TestSYNSourcesRefusesWhatIsNotAnEthernetPcap(t *testing.T) {
	p := filepath.Join(t.TempDir(), "junk")
	if err := os.WriteFile(p, []byte("not a capture at all, nowhere near"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SYNSources(p, netip.MustParseAddrPort("192.0.2.1:7777")); err == nil || !strings.Contains(err.Error(), "pcap") {
		t.Fatalf("SYNSources on junk: %v", err)
	}
}

func TestNetdevCarriesTheForwards(t *testing.T) {
	got := netdev([]string{"tcp:127.0.0.1:2222-:22"}, []string{"tcp:192.0.2.1:7777-tcp:127.0.0.1:40000"})
	want := "user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:2222-:22,guestfwd=tcp:192.0.2.1:7777-tcp:127.0.0.1:40000"
	if got != want {
		t.Fatalf("netdev = %q, want %q", got, want)
	}
}
