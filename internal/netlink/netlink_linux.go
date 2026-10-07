// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0
// Copyright The CryptOS Authors.

//go:build linux

package netlink

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

var seq atomic.Uint32

func next() uint32 { return seq.Add(1) }

func index(name string) (int, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifc.Index, nil
}

func open(groups uint32) (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, fmt.Errorf("netlink: socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("netlink: bind: %w", err)
	}
	return fd, nil
}

// request sends one request and waits for the kernel's ACK.
func request(msg []byte) error {
	fd, err := open(0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink: send: %w", err)
	}
	resp := make([]byte, unix.Getpagesize())
	n, _, err := unix.Recvfrom(fd, resp, 0)
	if err != nil {
		return fmt.Errorf("netlink: recv ack: %w", err)
	}
	errno, ok := parseAck(resp[:n])
	if !ok {
		return fmt.Errorf("netlink: unexpected reply (%d bytes)", n)
	}
	if errno != 0 {
		return fmt.Errorf("netlink: kernel refused the request: %w", syscall.Errno(-errno)) // #nosec G115 -- the kernel reports a negative errno
	}
	return nil
}

// dump sends a dump request and collects the messages up to NLMSG_DONE.
func dump(msg []byte) ([][]byte, error) {
	fd, err := open(0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("netlink: dump send: %w", err)
	}
	buf := make([]byte, 8*unix.Getpagesize())
	var out [][]byte
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("netlink: dump recv: %w", err)
		}
		data := buf[:n]
		for len(data) >= nlmsghdrLen {
			l := int(native.Uint32(data[0:4]))
			if l < nlmsghdrLen || l > len(data) {
				break
			}
			switch native.Uint16(data[4:6]) {
			case nlmsgDone:
				return out, nil
			case nlmsgError:
				if errno, _ := parseAck(data[:l]); errno != 0 {
					return nil, fmt.Errorf("netlink: dump: %w", syscall.Errno(-errno)) // #nosec G115 -- as above
				}
				return out, nil
			}
			out = append(out, append([]byte(nil), data[:l]...))
			if rtaAlign(l) > len(data) {
				break
			}
			data = data[rtaAlign(l):]
		}
	}
}

// LinkUp sets the interface up.
func LinkUp(name string) error {
	idx, err := index(name)
	if err != nil {
		return fmt.Errorf("netlink: %s: %w", name, err)
	}
	if err := request(buildLinkUpRequest(next(), idx)); err != nil {
		return fmt.Errorf("netlink: set %s up: %w", name, err)
	}
	return nil
}

// AddAddr adds or replaces p on the interface with the given lifetimes in
// seconds (Forever for a permanent address).
func AddAddr(name string, p netip.Prefix, valid, preferred uint32) error {
	idx, err := index(name)
	if err != nil {
		return fmt.Errorf("netlink: %s: %w", name, err)
	}
	if err := request(buildAddrRequest(next(), idx, p, valid, preferred)); err != nil {
		return fmt.Errorf("netlink: add %s to %s: %w", p, name, err)
	}
	return nil
}

// DelAddr removes p from the interface; an address already gone is not an
// error.
func DelAddr(name string, p netip.Prefix) error {
	idx, err := index(name)
	if err != nil {
		return fmt.Errorf("netlink: %s: %w", name, err)
	}
	if err := request(buildAddrDelRequest(next(), idx, p)); err != nil && !gone(err) {
		return fmt.Errorf("netlink: delete %s from %s: %w", p, name, err)
	}
	return nil
}

// Addrs lists the addresses on the interface.
func Addrs(name string) ([]Addr, error) {
	idx, err := index(name)
	if err != nil {
		return nil, fmt.Errorf("netlink: %s: %w", name, err)
	}
	msgs, err := dump(buildDumpRequest(next(), rtmGetAddr, ifaddrmsgLen))
	if err != nil {
		return nil, err
	}
	var out []Addr
	for _, a := range parseAddrMessages(msgs) {
		if a.Index == idx {
			out = append(out, a)
		}
	}
	return out, nil
}

// ReplaceDefaultRoute points the default route of gw's family on the
// interface at gw, at metric.
func ReplaceDefaultRoute(name string, gw netip.Addr, metric uint32, proto byte) error {
	idx, err := index(name)
	if err != nil {
		return fmt.Errorf("netlink: %s: %w", name, err)
	}
	if err := request(buildDefaultRouteRequest(next(), idx, gw, metric, proto)); err != nil {
		return fmt.Errorf("netlink: default route via %s on %s: %w", gw, name, err)
	}
	return nil
}

// DelDefaultRoute removes the interface's default route of one family
// (v6 false for IPv4) at metric; none there is not an error.
func DelDefaultRoute(name string, v6 bool, metric uint32) error {
	idx, err := index(name)
	if err != nil {
		return fmt.Errorf("netlink: %s: %w", name, err)
	}
	fam := byte(afInet)
	if v6 {
		fam = afInet6
	}
	if err := request(buildDefaultRouteDelRequest(next(), fam, idx, metric)); err != nil && !gone(err) {
		return fmt.Errorf("netlink: delete the default route on %s: %w", name, err)
	}
	return nil
}

// Routes lists the main table's routes out of the interface.
func Routes(name string) ([]Route, error) {
	idx, err := index(name)
	if err != nil {
		return nil, fmt.Errorf("netlink: %s: %w", name, err)
	}
	msgs, err := dump(buildDumpRequest(next(), rtmGetRoute, rtmsgLen))
	if err != nil {
		return nil, err
	}
	var out []Route
	for _, r := range parseRouteMessages(msgs) {
		if r.Oif == idx && r.Table == rtTableMain {
			out = append(out, r)
		}
	}
	return out, nil
}

// Neighbours lists the ARP and NDP entries on the interface.
func Neighbours(name string) ([]Neigh, error) {
	idx, err := index(name)
	if err != nil {
		return nil, fmt.Errorf("netlink: %s: %w", name, err)
	}
	msgs, err := dump(buildDumpRequest(next(), rtmGetNeigh, ndmsgLen))
	if err != nil {
		return nil, err
	}
	var out []Neigh
	for _, n := range parseNeighMessages(msgs) {
		if n.Index == idx {
			out = append(out, n)
		}
	}
	return out, nil
}

// Subscribe sends on the returned channel whenever a link, address or
// route changes, until ctx ends. Notices are coalesced: a receiver that
// is behind gets one send for many changes.
func Subscribe(ctx context.Context) (<-chan struct{}, error) {
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE)
	fd, err := open(groups)
	if err != nil {
		return nil, err
	}
	// A receive timeout lets the reader see ctx end.
	tv := unix.Timeval{Sec: 1}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netlink: receive timeout: %w", err)
	}
	ch := make(chan struct{}, 1)
	go func() {
		defer func() { _ = unix.Close(fd) }()
		defer close(ch)
		buf := make([]byte, 8*unix.Getpagesize())
		for {
			_, _, err := unix.Recvfrom(fd, buf, 0)
			if ctx.Err() != nil {
				return
			}
			switch {
			case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EINTR):
				continue
			case err != nil && !errors.Is(err, unix.ENOBUFS):
				return
			}
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}()
	return ch, nil
}

func gone(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && (errno == syscall.EADDRNOTAVAIL || errno == syscall.ENOENT || errno == syscall.ESRCH)
}
