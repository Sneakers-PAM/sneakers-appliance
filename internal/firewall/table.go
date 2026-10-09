// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package firewall is the appliance's management firewall: one nftables
// table, inet sneakers_mgmt, whose input chain runs at priority -10, before
// the k0s network stack's filter chains (spec 2, Section 3.5). It accepts
// established and related traffic, accepts 22 and 8443 only on the
// management interface (and on lo, so the box can reach itself), only once the first-boot step that opens them has
// run, and only from the allow-list, and drops every other packet to 22 and
// 8443. Other ports are left alone, apart from the service interface's
// rules spec 3 hands in. The whole table is rewritten in one netlink batch
// on every change.
package firewall

import (
	"fmt"
	"math/big"
	"net/netip"
	"slices"
	"strings"
)

// TableName and ChainName name what Apply writes.
const (
	TableName = "sneakers_mgmt"
	ChainName = "input"
	// Priority runs the chain before the standard filter priority (0).
	Priority = -10
)

// LoopbackIf is the loopback interface: a connection from the box to one of
// its own addresses comes in on it, whichever NIC holds the address.
const LoopbackIf = "lo"

// The management ports.
const (
	SSHPort   = 22
	HTTPSPort = 8443
)

// Table is everything the firewall is written from.
type Table struct {
	// MgmtIf is the management interface; 22 and 8443 are accepted only
	// there.
	MgmtIf string
	// AllowV4 and AllowV6 are the allow-list. Both empty accepts any
	// source on the management interface (first boot's default); when
	// either is set, a family with no prefixes has no way in.
	AllowV4, AllowV6 []netip.Prefix
	// Open22 and Open8443 are set by the first-boot steps that open them
	// (and stay set once setup is done).
	Open22, Open8443 bool
	// Service carries the product's port rules (spec 3); nil is none.
	Service *ServicePorts
}

// ServicePorts are the product's accept rules on the service interface.
type ServicePorts struct {
	Iface string
	Rules []PortRule
}

// PortRule accepts one port; no prefixes is any source.
type PortRule struct {
	// Protocol is tcp or udp.
	Protocol         string
	Port             uint16
	AllowV4, AllowV6 []netip.Prefix
}

// Family selects a rule's address family.
type Family int

// The families.
const (
	Any Family = iota
	V4
	V6
)

// Rule is one rule of the chain, in order.
type Rule struct {
	// Established is the conntrack rule; nothing else is set with it.
	Established bool
	// Iif matches the input interface; empty is any.
	Iif string
	// Family and Set match the source address against a named set.
	Family Family
	Set    string
	// Protocol is tcp or udp.
	Protocol string
	Port     uint16
	Accept   bool
}

func (r Rule) String() string {
	if r.Established {
		return "ct state established,related accept"
	}
	var b strings.Builder
	if r.Iif != "" {
		fmt.Fprintf(&b, "iifname %q ", r.Iif)
	}
	switch r.Family {
	case V4:
		fmt.Fprintf(&b, "ip saddr @%s ", r.Set)
	case V6:
		fmt.Fprintf(&b, "ip6 saddr @%s ", r.Set)
	}
	verdict := "drop"
	if r.Accept {
		verdict = "accept"
	}
	fmt.Fprintf(&b, "%s dport %d %s", r.Protocol, r.Port, verdict)
	return b.String()
}

// Set is one interval set of addresses.
type Set struct {
	Name      string
	V6        bool
	Intervals []Interval
}

// Ruleset is the planned table: its sets and its chain's rules.
type Ruleset struct {
	Sets  []Set
	Rules []Rule
}

// Plan turns t into the rules Apply writes.
func Plan(t Table) Ruleset {
	var rs Ruleset
	rs.Rules = append(rs.Rules, Rule{Established: true})
	any := len(t.AllowV4) == 0 && len(t.AllowV6) == 0
	if !any {
		if len(t.AllowV4) > 0 {
			rs.Sets = append(rs.Sets, Set{Name: "allow4", Intervals: Intervals(t.AllowV4)})
		}
		if len(t.AllowV6) > 0 {
			rs.Sets = append(rs.Sets, Set{Name: "allow6", V6: true, Intervals: Intervals(t.AllowV6)})
		}
	}
	for _, p := range []struct {
		port uint16
		open bool
	}{{SSHPort, t.Open22}, {HTTPSPort, t.Open8443}} {
		if !p.open || t.MgmtIf == "" {
			continue
		}
		// The box dialling its own address (the certificate swap's self-test
		// on :8443) arrives on lo, which only the box itself can send on.
		rs.Rules = append(rs.Rules, Rule{Iif: LoopbackIf, Protocol: "tcp", Port: p.port, Accept: true})
		base := Rule{Iif: t.MgmtIf, Protocol: "tcp", Port: p.port, Accept: true}
		if any {
			rs.Rules = append(rs.Rules, base)
			continue
		}
		if len(t.AllowV4) > 0 {
			r := base
			r.Family, r.Set = V4, "allow4"
			rs.Rules = append(rs.Rules, r)
		}
		if len(t.AllowV6) > 0 {
			r := base
			r.Family, r.Set = V6, "allow6"
			rs.Rules = append(rs.Rules, r)
		}
	}
	if t.Service != nil && t.Service.Iface != "" {
		for i, pr := range t.Service.Rules {
			base := Rule{Iif: t.Service.Iface, Protocol: pr.Protocol, Port: pr.Port, Accept: true}
			if len(pr.AllowV4) == 0 && len(pr.AllowV6) == 0 {
				rs.Rules = append(rs.Rules, base)
				continue
			}
			if len(pr.AllowV4) > 0 {
				name := fmt.Sprintf("svc%dv4", i+1)
				rs.Sets = append(rs.Sets, Set{Name: name, Intervals: Intervals(pr.AllowV4)})
				r := base
				r.Family, r.Set = V4, name
				rs.Rules = append(rs.Rules, r)
			}
			if len(pr.AllowV6) > 0 {
				name := fmt.Sprintf("svc%dv6", i+1)
				rs.Sets = append(rs.Sets, Set{Name: name, V6: true, Intervals: Intervals(pr.AllowV6)})
				r := base
				r.Family, r.Set = V6, name
				rs.Rules = append(rs.Rules, r)
			}
		}
	}
	rs.Rules = append(rs.Rules,
		Rule{Protocol: "tcp", Port: SSHPort},
		Rule{Protocol: "tcp", Port: HTTPSPort},
	)
	return rs
}

// Interval is an inclusive address range.
type Interval struct {
	First, Last netip.Addr
}

func (i Interval) String() string { return i.First.String() + "-" + i.Last.String() }

// Intervals merges prefixes of one family into sorted, disjoint ranges.
func Intervals(ps []netip.Prefix) []Interval {
	var in []Interval
	for _, p := range ps {
		p = p.Masked()
		in = append(in, Interval{First: p.Addr(), Last: lastAddr(p)})
	}
	slices.SortFunc(in, func(a, b Interval) int { return a.First.Compare(b.First) })
	var out []Interval
	for _, i := range in {
		if n := len(out); n > 0 {
			prev := &out[n-1]
			if next := prev.Last.Next(); !next.IsValid() || i.First.Compare(next) <= 0 {
				if i.Last.Compare(prev.Last) > 0 {
					prev.Last = i.Last
				}
				continue
			}
		}
		out = append(out, i)
	}
	return out
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr()
	size := a.BitLen()
	n := new(big.Int).SetBytes(a.AsSlice())
	host := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(size-p.Bits())), big.NewInt(1)) // #nosec G115 -- 0 to 128
	n.Or(n, host)
	b := n.FillBytes(make([]byte, size/8))
	out, _ := netip.AddrFromSlice(b)
	return out
}
