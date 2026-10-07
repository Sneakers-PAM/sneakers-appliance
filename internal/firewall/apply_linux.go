// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package firewall

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Apply writes t as the whole sneakers_mgmt table in one netlink batch: the
// table is added (a no-op when it's there), deleted and written again, so
// the kernel swaps the old table for the new one in a single transaction
// and no packet sees a half-written table.
func Apply(t Table) error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	return write(conn, Plan(t))
}

// Delete removes the table (a box being reset, and the tests).
func Delete() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
	conn.AddTable(tbl)
	conn.DelTable(tbl)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("firewall: delete %s: %w", TableName, err)
	}
	return nil
}

func write(conn *nftables.Conn, rs Ruleset) error {
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
	conn.AddTable(tbl)
	conn.DelTable(tbl)
	tbl = conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableName})
	sets := map[string]*nftables.Set{}
	for _, s := range rs.Sets {
		set := &nftables.Set{Table: tbl, Name: s.Name, KeyType: nftables.TypeIPAddr, Interval: true}
		if s.V6 {
			set.KeyType = nftables.TypeIP6Addr
		}
		if err := conn.AddSet(set, elements(s.Intervals)); err != nil {
			return fmt.Errorf("firewall: set %s: %w", s.Name, err)
		}
		sets[s.Name] = set
	}
	policy := nftables.ChainPolicyAccept
	chain := conn.AddChain(&nftables.Chain{
		Name: ChainName, Table: tbl, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityRef(Priority), Policy: &policy,
	})
	for _, r := range rs.Rules {
		conn.AddRule(&nftables.Rule{Table: tbl, Chain: chain, Exprs: exprs(r, sets)})
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("firewall: write %s: %w", TableName, err)
	}
	return nil
}

// elements are an interval set's elements: each range's first address,
// then the address after its last, flagged as the interval's end (left out
// when the range runs to the family's last address).
func elements(in []Interval) []nftables.SetElement {
	var out []nftables.SetElement
	for _, i := range in {
		out = append(out, nftables.SetElement{Key: i.First.AsSlice()})
		if next := i.Last.Next(); next.IsValid() {
			out = append(out, nftables.SetElement{Key: next.AsSlice(), IntervalEnd: true})
		}
	}
	return out
}

func ifname(name string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, name)
	return b
}

func exprs(r Rule, sets map[string]*nftables.Set) []expr.Any {
	verdict := expr.VerdictDrop
	if r.Accept {
		verdict = expr.VerdictAccept
	}
	if r.Established {
		return []expr.Any{
			&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
				Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:  binaryutil.NativeEndian.PutUint32(0)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
			&expr.Verdict{Kind: expr.VerdictAccept},
		}
	}
	var out []expr.Any
	if r.Iif != "" {
		out = append(out,
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(r.Iif)})
	}
	switch r.Family {
	case V4:
		set := sets[r.Set]
		out = append(out,
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID})
	case V6:
		set := sets[r.Set]
		out = append(out,
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
			&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID})
	}
	proto := byte(unix.IPPROTO_TCP)
	if r.Protocol == "udp" {
		proto = unix.IPPROTO_UDP
	}
	out = append(out,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(r.Port)},
		&expr.Verdict{Kind: verdict})
	return out
}
