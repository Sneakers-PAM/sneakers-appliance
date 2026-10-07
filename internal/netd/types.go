// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package netd is sneakers-netd (spec 2, Section 3.5): it applies the
// network settings over netlink, runs the DHCPv4, DHCPv6 and router
// advertisement clients (SLAAC itself is the kernel's), writes
// /run/sneakers/resolv.conf, keeps the clock with SNTP, writes the
// management firewall, runs the connectivity checks, and tells sshd and
// osadmin when the management addresses change. It serves the
// sneakers.appliance.netd.v1 NetworkService on /run/sneakers/netd.sock, to
// root only.
package netd

import (
	"context"
	"net/netip"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/firewall"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netlink"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/timesync"
)

// Link is one NIC.
type Link struct {
	Name   string
	MAC    string
	Up     bool
	Driver string
}

// System is the kernel as netd uses it. The Linux one is netlink, sysctl
// and nftables; the tests use a fake.
type System interface {
	Links() ([]Link, error)
	LinkUp(name string) error
	Addrs(name string) ([]netlink.Addr, error)
	AddAddr(name string, p netip.Prefix, valid, preferred uint32) error
	DelAddr(name string, p netip.Prefix) error
	ReplaceDefaultRoute(name string, gw netip.Addr, metric uint32, proto byte) error
	DelDefaultRoute(name string, v6 bool, metric uint32) error
	Routes(name string) ([]netlink.Route, error)
	// SetIPv6 sets the interface's IPv6 sysctls for mode: disabled when
	// off, router advertisements accepted (and SLAAC on in slaac mode)
	// otherwise.
	SetIPv6(name string, mode network.Mode6) error
	SetHostname(name string) error
	Firewall(t firewall.Table) error
	// Reach resolves gw's link-layer address (ARP or neighbour
	// discovery) on name.
	Reach(ctx context.Context, name string, gw netip.Addr) error
	// QueryDNS asks server for name; an answer of any kind, NXDOMAIN too,
	// means the server works.
	QueryDNS(ctx context.Context, server netip.Addr, name string) error
	// Subscribe sends whenever a link, address or route changes.
	Subscribe(ctx context.Context) (<-chan struct{}, error)
}

// Lease4 is a DHCPv4 lease.
type Lease4 struct {
	Addr     netip.Prefix
	Router   netip.Addr
	Lease    time.Duration
	DNS      []netip.Addr
	NTP      []string
	Hostname string
	Domain   string
	Search   []string
}

// Lease6 is what DHCPv6 gave: an address in stateful mode, and the
// options either way.
type Lease6 struct {
	// Addr is invalid for an information-only reply.
	Addr             netip.Prefix
	Valid, Preferred time.Duration
	DNS              []netip.Addr
	NTP              []string
	Search           []string
}

// RAInfo is what the last router advertisement said.
type RAInfo struct {
	RDNSS []netip.Addr
	// Search is the DNSSL option.
	Search []string
	// Managed and Other are the M and O flags.
	Managed, Other bool
}

// Workers run the DHCP and router advertisement clients on an interface
// until ctx ends, handing every result to report (nil when a lease is
// lost).
type Workers interface {
	DHCPv4(ctx context.Context, iface string, report func(*Lease4))
	DHCPv6(ctx context.Context, iface string, stateful bool, report func(*Lease6))
	RA(ctx context.Context, iface string, report func(*RAInfo))
}

// TimeSync is the SNTP engine (timesync.Engine).
type TimeSync interface {
	BootSync(ctx context.Context)
	Run(ctx context.Context)
	SyncNow(ctx context.Context)
	Status() timesync.Status
}

// PortRule is one of the product's service-interface rules (spec 3).
type PortRule struct {
	Protocol string
	Port     uint16
	// Allow is the sources; none is any.
	Allow []netip.Prefix
}

// CheckState is a check's result.
type CheckState string

// The results.
const (
	CheckOK     CheckState = "ok"
	CheckWarn   CheckState = "warn"
	CheckFailed CheckState = "failed"
)

// Check is one connectivity check.
type Check struct {
	// Name is link, address, gateway, dns or ntp.
	Name  string
	State CheckState
	// Code is the NET_* symbol when the check isn't ok.
	Code   string
	Detail string
	// Skippable is false for what setup can't continue past.
	Skippable bool
}

// Status is netd's live state.
type Status struct {
	Management, Service []string
	Hostname            string
	NTPSynced           bool
	NTPOffset           time.Duration
	SSHOpen, HTTPSOpen  bool
}

// Addresses is what Watch sends.
type Addresses struct {
	Management, Service []string
	Hostname            string
}
