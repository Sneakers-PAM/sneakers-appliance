// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ErrNoSuchName is a DNS server's answer that the name doesn't exist, or
// has no A or AAAA record.
var ErrNoSuchName = errors.New("the name isn't in DNS")

// udpWait is how long a lookup waits for a UDP answer before it asks over
// TCP instead.
const udpWait = 1500 * time.Millisecond

// Lookup asks server, and only server, for name's A and AAAA records. It
// asks over UDP and then, when no UDP answer comes or it's truncated, over
// TCP. The name is asked as it is: no search domains and no hosts file, so
// the answer is what that server says.
func Lookup(ctx context.Context, server netip.AddrPort, name string) ([]netip.Addr, error) {
	qname, err := dnsmessage.NewName(strings.TrimSuffix(strings.ToLower(name), ".") + ".")
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", name, err)
	}
	var out []netip.Addr
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		addrs, rc, err := query(ctx, server, qname, typ)
		if err != nil {
			return nil, err
		}
		switch rc {
		case dnsmessage.RCodeSuccess:
			out = append(out, addrs...)
		case dnsmessage.RCodeNameError:
			return nil, ErrNoSuchName
		default:
			return nil, fmt.Errorf("the DNS server %s answered %s for %s", server.Addr(), rc, name)
		}
	}
	if len(out) == 0 {
		return nil, ErrNoSuchName
	}
	return out, nil
}

func query(ctx context.Context, server netip.AddrPort, name dnsmessage.Name, typ dnsmessage.Type) ([]netip.Addr, dnsmessage.RCode, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, 0, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		return nil, 0, err
	}
	msg, err := b.Finish()
	if err != nil {
		return nil, 0, err
	}
	resp, uerr := exchangeUDP(ctx, server, msg, id)
	h, addrs, perr := parseAnswer(resp, id, typ)
	if uerr != nil || perr != nil || h.Truncated {
		resp, err = exchangeTCP(ctx, server, msg)
		if err != nil {
			if uerr != nil {
				return nil, 0, fmt.Errorf("the DNS server %s didn't answer over UDP (%v) or TCP (%w)", server.Addr(), uerr, err)
			}
			return nil, 0, fmt.Errorf("the DNS server %s didn't answer over TCP: %w", server.Addr(), err)
		}
		if h, addrs, perr = parseAnswer(resp, id, typ); perr != nil {
			return nil, 0, perr
		}
	}
	return addrs, h.RCode, nil
}

func exchangeUDP(ctx context.Context, server netip.AddrPort, msg []byte, id uint16) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", server.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	deadline := time.Now().Add(udpWait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = c.SetDeadline(deadline)
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, 1232)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 2 && binary.BigEndian.Uint16(buf[:2]) == id {
			return buf[:n], nil
		}
	}
}

func exchangeTCP(ctx context.Context, server netip.AddrPort, msg []byte) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", server.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(len(msg))) // #nosec G115 -- one question
	if _, err := c.Write(append(out, msg...)); err != nil {
		return nil, err
	}
	var n [2]byte
	if _, err := io.ReadFull(c, n[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(n[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// parseAnswer reads a reply to query id: its header and the addresses of
// type typ in its answer section (a CNAME's target's included).
func parseAnswer(resp []byte, id uint16, typ dnsmessage.Type) (dnsmessage.Header, []netip.Addr, error) {
	if resp == nil {
		return dnsmessage.Header{}, nil, errors.New("no reply")
	}
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return h, nil, fmt.Errorf("a reply that doesn't parse: %w", err)
	}
	if h.ID != id || !h.Response {
		return h, nil, errors.New("a reply to another query")
	}
	if err := p.SkipAllQuestions(); err != nil {
		return h, nil, fmt.Errorf("a reply that doesn't parse: %w", err)
	}
	var out []netip.Addr
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return h, out, nil
		}
		if err != nil {
			return h, nil, fmt.Errorf("a reply that doesn't parse: %w", err)
		}
		switch {
		case rh.Type == typ && typ == dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return h, nil, err
			}
			out = append(out, netip.AddrFrom4(r.A))
		case rh.Type == typ && typ == dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return h, nil, err
			}
			out = append(out, netip.AddrFrom16(r.AAAA))
		default:
			if err := p.SkipAnswer(); err != nil {
				return h, nil, err
			}
		}
	}
}
