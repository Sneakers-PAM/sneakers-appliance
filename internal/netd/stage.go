// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"reflect"
	"slices"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netlink"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

// staged is a change waiting for its commit. It lives in netd's memory and
// nowhere else: every surface sees the same one, an SSH reconnect doesn't
// touch it, and a restart drops it, so a box can't come back on a change
// nobody committed.
type staged struct {
	id string
	// base is what was live when it was staged. next is a whole set of
	// settings, so committing it over anything else would undo that change.
	base, next network.Settings
}

// Stage records next for a later Commit, replacing any stage before it, and
// returns the id Commit takes. Nothing changes live.
func (d *Daemon) Stage(next network.Settings) (string, error) {
	if err := network.Validate(next); err != nil {
		return "", err
	}
	if err := d.knownNICs(next); err != nil {
		return "", err
	}
	base, _ := d.Get()
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	st := &staged{id: hex.EncodeToString(b), base: base, next: next}
	d.mu.Lock()
	d.staged = st
	d.mu.Unlock()
	d.o.Logger.Info("netd: settings staged", log.F("staged", st.id), log.F("management", next.Management.Name))
	return st.id, nil
}

// Staged returns what's staged and its id.
func (d *Daemon) Staged() (network.Settings, string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.staged == nil {
		return network.Settings{}, "", false
	}
	return d.staged.next, d.staged.id, true
}

// DiscardStaged drops what's staged.
func (d *Daemon) DiscardStaged() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.staged != nil {
		d.o.Logger.Info("netd: staged settings dropped", log.F("staged", d.staged.id))
	}
	d.staged = nil
}

func stagedErr(reason string) error {
	return codes.Wrap(codes.NetInvalid, &network.FieldError{Field: "staged", Reason: reason})
}

// Commit applies and saves the stage id names, for good: no window, no undo
// file. Its gateways are tested first, and a refusal leaves everything as it
// was, the stage included. It returns the gateways that answered.
func (d *Daemon) Commit(ctx context.Context, id string) ([]string, error) {
	d.mu.Lock()
	st := d.staged
	d.mu.Unlock()
	switch {
	case st == nil:
		return nil, stagedErr("nothing is staged")
	case st.id != id:
		return nil, stagedErr("the staged change isn't the one you reviewed; look at it again")
	}
	prev, _ := d.Get()
	if !reflect.DeepEqual(prev, st.base) {
		return nil, stagedErr("the settings changed after this was staged; discard it and stage it again")
	}
	var tested []string
	err := d.keep(prev, st.next, func() error {
		var err error
		tested, err = d.testGateways(ctx, prev, st.next)
		return err
	})
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	if d.staged == st {
		d.staged = nil
	}
	d.mu.Unlock()
	d.o.Logger.Info("netd: staged settings committed and kept", log.F("staged", id), log.F("management", st.next.Management.Name), log.F("gateways", len(tested)))
	return tested, nil
}

// SetAndKeep validates next, applies it and keeps it, with no window: the
// caller has shown the change and been told to go ahead.
func (d *Daemon) SetAndKeep(next network.Settings) error {
	if err := network.Validate(next); err != nil {
		return err
	}
	if err := d.knownNICs(next); err != nil {
		return err
	}
	prev, _ := d.Get()
	if err := d.keep(prev, next, nil); err != nil {
		return err
	}
	d.o.Logger.Info("netd: settings changed and kept", log.F("management", next.Management.Name))
	return nil
}

func (d *Daemon) keep(prev, next network.Settings, check func() error) error {
	return d.rev.Keep(prev, next, check, func(s network.Settings) error {
		if s.Management.Name == "" {
			return nil
		}
		return d.applyAndSave(s, true)
	})
}

// testLifetime is how long, in seconds, a test address can outlive netd.
const testLifetime = 30

// gatewayTest is one family's staged address and gateway.
type gatewayTest struct {
	addr netip.Prefix
	gw   netip.Addr
}

// gatewayTests are the families next changes that name a gateway. One the
// change leaves alone isn't tested, and DHCP and SLAAC have no staged
// gateway to test.
func gatewayTests(prev, next network.Settings) []gatewayTest {
	p, n := prev.Management, next.Management
	moved := p.Name != n.Name
	var out []gatewayTest
	if n.IPv4.Mode == network.V4Static && n.IPv4.Gateway.IsValid() && (moved || p.IPv4 != n.IPv4) {
		out = append(out, gatewayTest{n.IPv4.Address, n.IPv4.Gateway})
	}
	if n.IPv6.Mode == network.V6Static && n.IPv6.Gateway.IsValid() && (moved || p.IPv6 != n.IPv6) {
		out = append(out, gatewayTest{n.IPv6.Address, n.IPv6.Gateway})
	}
	return out
}

func (d *Daemon) testGateways(ctx context.Context, prev, next network.Settings) ([]string, error) {
	var tested []string
	for _, t := range gatewayTests(prev, next) {
		if err := d.testGateway(ctx, prev, next.Management.Name, t); err != nil {
			d.o.Logger.Warn("netd: the commit was refused", log.F("gateway", t.gw.String()), log.F("from", t.addr.String()), log.F("error", err.Error()))
			return nil, err
		}
		d.o.Logger.Info("netd: the staged gateway answers", log.F("gateway", t.gw.String()), log.F("from", t.addr.String()))
		tested = append(tested, t.gw.String())
	}
	return tested, nil
}

// testGateway asks t.gw from t.addr without touching the addresses in use:
// t.addr goes on the interface as an extra address, so the kernel can reach
// a gateway on a subnet the box isn't on yet, and comes off again however the
// test ends. It's hidden from Status and Watch, because sshd and osadmin
// rebind to what those report; applyMu keeps a lease or an apply from
// reconciling it away meanwhile. Its short lifetime clears it even if netd
// dies here, and with no preferred lifetime nothing else picks it as a source.
func (d *Daemon) testGateway(ctx context.Context, prev network.Settings, name string, t gatewayTest) error {
	d.applyMu.Lock()
	defer d.applyMu.Unlock()
	sys, lg := d.o.Sys, d.o.Logger
	v6 := t.addr.Addr().Is6()
	if err := sys.LinkUp(name); err != nil {
		return codes.Wrap(codes.NetGateway, err)
	}
	if v6 && prev.Management.Name == name && prev.Management.IPv6.Mode == network.V6Off {
		if err := sys.SetIPv6(name, network.V6Static); err != nil {
			return codes.Wrap(codes.NetGateway, err)
		}
		defer func() {
			if err := sys.SetIPv6(name, network.V6Off); err != nil {
				lg.Error(err, "netd: IPv6 wasn't turned off again after the gateway test", log.F("iface", name))
			}
		}()
	}
	addrs, err := sys.Addrs(name)
	if err != nil {
		return codes.Wrap(codes.NetGateway, err)
	}
	// IPv6 keys an address by its IP alone: adding the live IP with another
	// prefix would replace it, and removing that would drop it.
	live := slices.ContainsFunc(addrs, func(a netlink.Addr) bool {
		return a.Prefix == t.addr || v6 && a.Prefix.Addr() == t.addr.Addr()
	})
	if !live {
		d.hide(t.addr, true)
		defer d.hide(t.addr, false)
		if err := sys.AddAddr(name, t.addr, testLifetime, 0); err != nil {
			return codes.Wrap(codes.NetGateway, err)
		}
		defer func() {
			if err := sys.DelAddr(name, t.addr); err != nil {
				lg.Error(err, "netd: the test address wasn't removed; it expires on its own", log.F("iface", name), log.F("addr", t.addr.String()), log.F("seconds", testLifetime))
			}
		}()
		lg.Debug("netd: test address added", log.F("iface", name), log.F("addr", t.addr.String()))
		if err := d.waitDAD(ctx, name, t.addr); err != nil {
			return err
		}
	}
	pctx, cancel := context.WithTimeout(ctx, probeWait)
	defer cancel()
	if err := sys.ReachFrom(pctx, name, t.addr.Addr(), t.gw); err != nil {
		return codes.New(codes.NetGateway, "the gateway %s doesn't answer from %s, so nothing was changed: %v", t.gw, t.addr, err)
	}
	return nil
}

// waitDAD returns once p can be sent from. The kernel deletes an address
// that fails DAD unless it's permanent, which a test address isn't, so gone
// counts as failed too.
func (d *Daemon) waitDAD(ctx context.Context, name string, p netip.Prefix) error {
	deadline := time.Now().Add(dadWait)
	for {
		addrs, err := d.o.Sys.Addrs(name)
		if err != nil {
			return codes.Wrap(codes.NetGateway, err)
		}
		i := slices.IndexFunc(addrs, func(a netlink.Addr) bool { return a.Prefix == p })
		switch {
		case i < 0 || addrs[i].DADFailed():
			return codes.New(codes.NetGateway, "the address %s is already in use on the network, so nothing was changed", p)
		case !addrs[i].Tentative() || time.Now().After(deadline) || ctx.Err() != nil:
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// hide keeps p out of what usable reports while it's being tested.
func (d *Daemon) hide(p netip.Prefix, on bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if on {
		d.testing = p
	} else {
		d.testing = netip.Prefix{}
	}
}
