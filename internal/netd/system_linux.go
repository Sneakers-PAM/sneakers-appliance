// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/firewall"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netlink"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
)

// Linux is the System on the box: rtnetlink, the per-interface sysctls in
// /proc/sys, sethostname and nftables.
type Linux struct {
	// Proc and Sys default to /proc and /sys.
	Proc, Sys string
}

func (l Linux) proc() string {
	if l.Proc == "" {
		return "/proc"
	}
	return l.Proc
}

func (l Linux) sys() string {
	if l.Sys == "" {
		return "/sys"
	}
	return l.Sys
}

// Links lists the interfaces with their MAC, carrier and driver.
func (l Linux) Links() ([]Link, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Link
	for _, i := range ifs {
		k := Link{Name: i.Name, MAC: i.HardwareAddr.String()}
		state, _ := os.ReadFile(filepath.Join(l.sys(), "class", "net", i.Name, "operstate")) // #nosec G304 -- a sysfs attribute
		switch strings.TrimSpace(string(state)) {
		case "up":
			k.Up = true
		case "unknown":
			k.Up = i.Flags&net.FlagRunning != 0
		}
		if drv, err := os.Readlink(filepath.Join(l.sys(), "class", "net", i.Name, "device", "driver")); err == nil {
			k.Driver = filepath.Base(drv)
		}
		out = append(out, k)
	}
	return out, nil
}

// LinkUp sets the interface up.
func (Linux) LinkUp(name string) error { return netlink.LinkUp(name) }

// Addrs lists the interface's addresses.
func (Linux) Addrs(name string) ([]netlink.Addr, error) { return netlink.Addrs(name) }

// AddAddr adds or replaces an address.
func (Linux) AddAddr(name string, p netip.Prefix, valid, preferred uint32) error {
	return netlink.AddAddr(name, p, valid, preferred)
}

// DelAddr removes an address.
func (Linux) DelAddr(name string, p netip.Prefix) error { return netlink.DelAddr(name, p) }

// ReplaceDefaultRoute sets a default route.
func (Linux) ReplaceDefaultRoute(name string, gw netip.Addr, metric uint32, proto byte) error {
	return netlink.ReplaceDefaultRoute(name, gw, metric, proto)
}

// DelDefaultRoute removes a default route.
func (Linux) DelDefaultRoute(name string, v6 bool, metric uint32) error {
	return netlink.DelDefaultRoute(name, v6, metric)
}

// Routes lists the interface's routes.
func (Linux) Routes(name string) ([]netlink.Route, error) { return netlink.Routes(name) }

// SetIPv6 writes the interface's IPv6 sysctls for mode. accept_ra is 2
// because k0s turns forwarding on, and with 1 the kernel would then ignore
// router advertisements.
func (l Linux) SetIPv6(name string, mode network.Mode6) error {
	vals := map[string]string{"disable_ipv6": "0", "accept_ra": "2", "autoconf": "0"}
	switch mode {
	case network.V6Off:
		vals = map[string]string{"disable_ipv6": "1"}
	case network.V6SLAAC:
		vals["autoconf"] = "1"
	case network.V6Static:
		vals["accept_ra"] = "0"
	}
	dir := filepath.Join(l.proc(), "sys", "net", "ipv6", "conf", name)
	var errs []error
	// disable_ipv6 first: the others can't be set while IPv6 is off.
	for _, k := range []string{"disable_ipv6", "accept_ra", "autoconf"} {
		v, ok := vals[k]
		if !ok {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o644); err != nil { // #nosec G306 -- a sysctl
			errs = append(errs, fmt.Errorf("netd: %s/%s: %w", name, k, err))
		}
	}
	return errors.Join(errs...)
}

// SetHostname sets the kernel's host name.
func (Linux) SetHostname(name string) error { return unix.Sethostname([]byte(name)) }

// Firewall writes the management table.
func (Linux) Firewall(t firewall.Table) error { return firewall.Apply(t) }

// Reach sends gw a datagram, which has the kernel resolve its link-layer
// address, then waits for the neighbour entry.
func (Linux) Reach(ctx context.Context, name string, gw netip.Addr) error {
	addr := netip.AddrPortFrom(gw, 9)
	if gw.IsLinkLocalUnicast() {
		addr = netip.AddrPortFrom(gw.WithZone(name), 9)
	}
	var d net.Dialer
	if c, err := d.DialContext(ctx, "udp", addr.String()); err == nil {
		_, _ = c.Write([]byte{0})
		_ = c.Close()
	}
	for {
		ns, err := netlink.Neighbours(name)
		if err != nil {
			return err
		}
		for _, n := range ns {
			if n.Addr == gw.WithZone("") {
				switch {
				case n.Usable():
					return nil
				case n.State&netlink.NUDFailed != 0:
					return errors.New("no ARP or neighbour discovery answer")
				}
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("no ARP or neighbour discovery answer in time")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// QueryDNS asks server for name over UDP.
func (Linux) QueryDNS(ctx context.Context, server netip.Addr, name string) error {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", netip.AddrPortFrom(server, 53).String())
	}}
	_, err := r.LookupNetIP(ctx, "ip", name)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return nil
	}
	return err
}

// Subscribe watches the kernel's change notices.
func (Linux) Subscribe(ctx context.Context) (<-chan struct{}, error) { return netlink.Subscribe(ctx) }
