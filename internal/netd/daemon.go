// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/firewall"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netlink"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/timesync"
)

// Route metrics: the management interface's default routes win over the
// service interface's.
const (
	mgmtMetric    = 100
	serviceMetric = 200
)

// Options wire a Daemon.
type Options struct {
	// StateDir is the state volume's /var/lib/sneakers: settings/network.yaml
	// (and network.prev.yaml during a change's window), setup/done.
	StateDir string
	// RunDir is /run/sneakers: resolv.conf and netd/ports.json.
	RunDir  string
	Sys     System
	Workers Workers
	// NewTimeSync makes the SNTP engine for servers.
	NewTimeSync func(servers []string, src timesync.Source) TimeSync
	Clock       clock.Clock
	Logger      log.Logger
	// Fallback is the box's own name (internal/boxname): the kernel host
	// name while neither the settings nor DHCP give one. It is never
	// reported as the host name, so certificates don't take it.
	Fallback string
}

// Daemon is netd's state and logic.
type Daemon struct {
	o   Options
	rev *network.Reverter

	// applyMu serialises changes to the interfaces.
	applyMu sync.Mutex

	mu       sync.Mutex
	ctx      context.Context
	settings network.Settings
	// applied is what configure last applied per role, so an unchanged
	// family is left alone.
	applied  map[string]*network.Interface
	obs      map[string]*observed
	ports    ports
	service  []PortRule
	table    *firewall.Table
	hostname string
	// kernel is the host name last given to the kernel.
	kernel   string
	resolv   string
	ntp      TimeSync
	ntpKey   string
	ntpStop  context.CancelFunc
	last     Addresses
	haveLast bool
	subs     map[int]chan Addresses
	nextSub  int
	noNIC    bool
}

// observed is what the clients learnt on one interface.
type observed struct {
	stop4, stop6 context.CancelFunc
	ctx4, ctx6   context.Context
	lease4       *Lease4
	lease6       *Lease6
	ra           *RAInfo
	info         bool
}

type ports struct {
	SSH   bool `json:"ssh"`
	HTTPS bool `json:"https"`
}

// New loads the settings: network.prev.yaml when a change was left
// unconfirmed (it is undone), else network.yaml, else the first-boot
// defaults on the first NIC with a link.
func New(o Options) (*Daemon, error) {
	if o.Logger == nil {
		o.Logger = log.Nop()
	}
	if o.Clock == nil {
		o.Clock = clock.Real{}
	}
	if o.Sys == nil || o.Workers == nil || o.NewTimeSync == nil {
		return nil, errors.New("netd: Sys, Workers and NewTimeSync are required")
	}
	d := &Daemon{o: o, applied: map[string]*network.Interface{}, obs: map[string]*observed{}, subs: map[int]chan Addresses{}}
	d.rev = network.NewReverter(o.Clock, network.RevertOptions{Logger: o.Logger, OnRevert: d.reverted})
	if b, err := os.ReadFile(d.portsFile()); err == nil { // #nosec G304 -- netd's own file
		if err := json.Unmarshal(b, &d.ports); err != nil {
			o.Logger.Warn("netd: ports.json doesn't parse; 22 and 8443 stay closed", log.F("error", err.Error()))
		}
	}
	return d, nil
}

func (d *Daemon) settingsFile() string {
	return filepath.Join(d.o.StateDir, "settings", "network.yaml")
}
func (d *Daemon) prevFile() string {
	return filepath.Join(d.o.StateDir, "settings", "network.prev.yaml")
}
func (d *Daemon) portsFile() string { return filepath.Join(d.o.RunDir, "netd", "ports.json") }
func (d *Daemon) setupDone() bool {
	_, err := os.Stat(filepath.Join(d.o.StateDir, "setup", "done"))
	return err == nil
}

// Start applies the settings and starts watching the kernel. It returns
// once the first apply is done; the clients keep running until ctx ends.
func (d *Daemon) Start(ctx context.Context) error {
	lg := d.o.Logger
	d.mu.Lock()
	d.ctx = ctx
	d.mu.Unlock()
	if err := d.o.Sys.LinkUp("lo"); err != nil {
		lg.Warn("netd: loopback not brought up", log.F("error", err.Error()))
	}
	s, persist, err := d.load()
	if err != nil {
		return err
	}
	notices, err := d.o.Sys.Subscribe(ctx)
	if err != nil {
		lg.Warn("netd: no kernel change notices; address events come from the clients only", log.F("error", err.Error()))
	}
	if s.Management.Name == "" {
		d.mu.Lock()
		d.noNIC = true
		d.mu.Unlock()
		lg.Warn("netd: no network interface yet; waiting for one")
		if err := d.refresh(); err != nil {
			lg.Error(err, "netd: refresh with no interface")
		}
	} else if err := d.applyAndSave(s, persist); err != nil {
		lg.Error(err, "netd: the settings didn't apply fully")
	}
	go func() {
		<-ctx.Done()
		d.stopAll()
	}()
	if notices != nil {
		go d.watchKernel(ctx, notices)
	}
	lg.Info("netd: started", log.F("management", s.Management.Name))
	return nil
}

func (d *Daemon) load() (network.Settings, bool, error) {
	lg := d.o.Logger
	if prev, err := network.ReadFile(d.prevFile()); err == nil {
		lg.Warn("netd: a network change was left unconfirmed; undoing it", log.F("error", codes.Describe(codes.New(codes.NetReverted, "the network change wasn't confirmed and was undone at start"))))
		_ = os.Remove(d.prevFile())
		return prev, true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		lg.Error(err, "netd: network.prev.yaml unreadable; ignoring it")
	}
	s, err := network.ReadFile(d.settingsFile())
	switch {
	case err == nil:
		return s, false, nil
	case !errors.Is(err, os.ErrNotExist):
		lg.Error(err, "netd: network.yaml unreadable; using the defaults")
	}
	nic, err := d.firstNIC()
	if err != nil {
		return network.Settings{}, false, err
	}
	if nic == "" {
		return network.Settings{}, false, nil
	}
	lg.Info("netd: no settings yet; DHCP and SLAAC on the first NIC", log.F("nic", nic))
	return network.Defaults(nic), false, nil
}

// firstNIC is the first NIC in bus order with a link, else the first in
// bus order. Bus order holds across reboots where interface names may not.
func (d *Daemon) firstNIC() (string, error) {
	links, err := d.Interfaces()
	if err != nil {
		return "", err
	}
	for _, l := range links {
		if l.Up {
			return l.Name, nil
		}
	}
	if len(links) > 0 {
		return links[0].Name, nil
	}
	return "", nil
}

// Interfaces lists the physical NICs by bus order, then MAC. Virtual
// interfaces are left out: they are never the management or service
// interface.
func (d *Daemon) Interfaces() ([]Link, error) {
	links, err := d.o.Sys.Links()
	if err != nil {
		return nil, err
	}
	all := len(links)
	links = slices.DeleteFunc(links, func(l Link) bool { return !l.Physical() })
	slices.SortFunc(links, func(a, b Link) int {
		if c := strings.Compare(a.Bus, b.Bus); c != 0 {
			return c
		}
		if c := strings.Compare(a.MAC, b.MAC); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	d.o.Logger.Debug("netd: physical NICs", log.F("nics", len(links)), log.F("virtual", all-len(links)))
	return links, nil
}

// Get returns the applied settings and whether a change waits for its
// confirmation.
func (d *Daemon) Get() (network.Settings, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.settings, d.rev.Pending()
}

// PendingChange returns the change that waits for its confirmation.
func (d *Daemon) PendingChange() (network.Pending, bool) { return d.rev.PendingChange() }

// LastChange returns how the most recent change ended.
func (d *Daemon) LastChange() (network.Outcome, bool) { return d.rev.Last() }

// Set validates next, applies it and starts the 120-second window.
func (d *Daemon) Set(next network.Settings) (string, error) {
	if err := network.Validate(next); err != nil {
		return "", err
	}
	if err := d.knownNICs(next); err != nil {
		return "", err
	}
	prev, _ := d.Get()
	if !d.rev.Pending() {
		if err := network.WriteFile(d.prevFile(), prev); err != nil {
			return "", err
		}
	}
	tok, err := d.rev.Apply(prev, next, func(s network.Settings) error { return d.applyAndSave(s, true) })
	if err != nil {
		if !codes.Is(err, codes.NetInvalid) || network.Field(err) != "pending" {
			_ = os.Remove(d.prevFile())
		}
		return "", err
	}
	d.o.Logger.Info("netd: settings changed; waiting for the confirmation", log.F("management", next.Management.Name))
	return tok, nil
}

func (d *Daemon) knownNICs(s network.Settings) error {
	links, err := d.Interfaces()
	if err != nil {
		return err
	}
	has := func(n string) bool { return slices.ContainsFunc(links, func(l Link) bool { return l.Name == n }) }
	if !has(s.Management.Name) {
		return codes.Wrap(codes.NetInvalid, &network.FieldError{Field: "management.name", Reason: fmt.Sprintf("the box has no physical network interface %q", s.Management.Name)})
	}
	if s.Service != nil && !has(s.Service.Name) {
		return codes.Wrap(codes.NetInvalid, &network.FieldError{Field: "service.name", Reason: fmt.Sprintf("the box has no physical network interface %q", s.Service.Name)})
	}
	return nil
}

// Confirm keeps the pending change.
func (d *Daemon) Confirm(token string) error {
	if err := d.rev.Confirm(token); err != nil {
		return err
	}
	if err := os.Remove(d.prevFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		d.o.Logger.Warn("netd: network.prev.yaml not removed", log.F("error", err.Error()))
	}
	return nil
}

func (d *Daemon) reverted(network.Settings, error) {
	if err := os.Remove(d.prevFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		d.o.Logger.Warn("netd: network.prev.yaml not removed", log.F("error", err.Error()))
	}
}

// SetManagementPorts opens or closes 22 and 8443; the choice is kept in
// /run, so it lasts until the next boot.
func (d *Daemon) SetManagementPorts(ssh, https bool) error {
	d.mu.Lock()
	d.ports = ports{SSH: ssh, HTTPS: https}
	p := d.ports
	d.mu.Unlock()
	b, _ := json.Marshal(p)
	if err := os.MkdirAll(filepath.Dir(d.portsFile()), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(d.portsFile(), b, 0o600); err != nil {
		return err
	}
	d.o.Logger.Info("netd: management ports set", log.F("ssh", ssh), log.F("https", https))
	return d.refresh()
}

// SetServicePorts replaces the product's service-interface rules.
func (d *Daemon) SetServicePorts(rules []PortRule) error {
	for i, r := range rules {
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return codes.Wrap(codes.NetInvalid, &network.FieldError{Field: fmt.Sprintf("rules[%d].protocol", i), Reason: "use tcp or udp"})
		}
		if r.Port == 0 {
			return codes.Wrap(codes.NetInvalid, &network.FieldError{Field: fmt.Sprintf("rules[%d].port", i), Reason: "give a port from 1 to 65535"})
		}
	}
	d.mu.Lock()
	d.service = slices.Clone(rules)
	d.mu.Unlock()
	return d.refresh()
}

// applyAndSave applies s, records it, and persists it when save is set.
func (d *Daemon) applyAndSave(s network.Settings, save bool) error {
	d.applyMu.Lock()
	defer d.applyMu.Unlock()
	started := time.Now()
	var errs []error
	d.mu.Lock()
	d.settings = s
	d.noNIC = false
	d.mu.Unlock()
	errs = append(errs, d.configure("management", &s.Management, mgmtMetric))
	errs = append(errs, d.configure("service", s.Service, serviceMetric))
	if save {
		errs = append(errs, network.WriteFile(d.settingsFile(), s))
	}
	errs = append(errs, d.refresh())
	err := errors.Join(errs...)
	d.o.Logger.Info("netd: settings applied", log.F("management", s.Management.Name), log.F("ipv4", string(s.Management.IPv4.Mode)), log.F("ipv6", string(s.Management.IPv6.Mode)), log.F("ms", time.Since(started).Milliseconds()), log.F("ok", err == nil))
	return err
}

// configure brings one role's interface to i, family by family, leaving
// a family whose settings didn't change alone.
func (d *Daemon) configure(role string, i *network.Interface, metric uint32) error {
	sys, lg := d.o.Sys, d.o.Logger
	d.mu.Lock()
	old := d.applied[role]
	ctx := d.ctx
	d.mu.Unlock()
	if old != nil && (i == nil || old.Name != i.Name) {
		d.stopIface(old.Name, true, true)
	}
	if i == nil {
		d.mu.Lock()
		delete(d.applied, role)
		d.mu.Unlock()
		return nil
	}
	same := old != nil && old.Name == i.Name
	v4Same := same && old.IPv4 == i.IPv4
	v6Same := same && old.IPv6 == i.IPv6
	var errs []error
	if err := sys.LinkUp(i.Name); err != nil {
		errs = append(errs, err)
	}
	if !v6Same {
		d.stopIface(i.Name, false, true)
		if err := sys.SetIPv6(i.Name, i.IPv6.Mode); err != nil {
			errs = append(errs, err)
		}
		var want []netip.Prefix
		if i.IPv6.Mode == network.V6Static {
			want = append(want, i.IPv6.Address)
		}
		if i.IPv6.Mode != network.V6Off {
			errs = append(errs, d.reconcile(i.Name, true, want, i.IPv6.Mode == network.V6SLAAC))
		}
		switch {
		case i.IPv6.Mode == network.V6Static && i.IPv6.Gateway.IsValid():
			errs = append(errs, sys.ReplaceDefaultRoute(i.Name, i.IPv6.Gateway, metric, netlink.ProtoStatic))
		case i.IPv6.Mode == network.V6Static:
			errs = append(errs, sys.DelDefaultRoute(i.Name, true, metric))
		}
		if i.IPv6.Mode == network.V6SLAAC || i.IPv6.Mode == network.V6DHCPv6 {
			wctx := d.startFamily(ctx, i.Name, true)
			go d.o.Workers.RA(wctx, i.Name, func(ra *RAInfo) { d.onRA(wctx, i.Name, metric, ra) })
			if i.IPv6.Mode == network.V6DHCPv6 {
				go d.o.Workers.DHCPv6(wctx, i.Name, true, func(l *Lease6) { d.onLease6(wctx, i.Name, l) })
			}
		}
		lg.Debug("netd: IPv6 configured", log.F("iface", i.Name), log.F("mode", string(i.IPv6.Mode)))
	}
	if !v4Same {
		d.stopIface(i.Name, true, false)
		var want []netip.Prefix
		if i.IPv4.Mode == network.V4Static {
			want = append(want, i.IPv4.Address)
		}
		errs = append(errs, d.reconcile(i.Name, false, want, false))
		if i.IPv4.Mode == network.V4Static && i.IPv4.Gateway.IsValid() {
			errs = append(errs, sys.ReplaceDefaultRoute(i.Name, i.IPv4.Gateway, metric, netlink.ProtoStatic))
		} else {
			errs = append(errs, sys.DelDefaultRoute(i.Name, false, metric))
		}
		if i.IPv4.Mode == network.V4DHCP {
			wctx := d.startFamily(ctx, i.Name, false)
			go d.o.Workers.DHCPv4(wctx, i.Name, func(l *Lease4) { d.onLease4(wctx, i.Name, metric, l) })
		}
		lg.Debug("netd: IPv4 configured", log.F("iface", i.Name), log.F("mode", string(i.IPv4.Mode)))
	}
	cp := *i
	d.mu.Lock()
	d.applied[role] = &cp
	d.mu.Unlock()
	return errors.Join(errs...)
}

// reconcile leaves exactly want among the interface's global addresses of
// one family; with keepKernel the kernel's own (SLAAC, not permanent)
// addresses stay too.
func (d *Daemon) reconcile(name string, v6 bool, want []netip.Prefix, keepKernel bool) error {
	addrs, err := d.o.Sys.Addrs(name)
	if err != nil {
		return err
	}
	var errs []error
	for _, a := range addrs {
		ip := a.Prefix.Addr()
		if ip.Is6() != v6 || ip.IsLinkLocalUnicast() || slices.Contains(want, a.Prefix) {
			continue
		}
		if keepKernel && a.Flags&netlink.FlagPermanent == 0 {
			continue
		}
		d.o.Logger.Debug("netd: removing an address", log.F("iface", name), log.F("addr", a.Prefix.String()))
		errs = append(errs, d.o.Sys.DelAddr(name, a.Prefix))
	}
	for _, p := range want {
		errs = append(errs, d.o.Sys.AddAddr(name, p, netlink.Forever, netlink.Forever))
	}
	return errors.Join(errs...)
}

func (d *Daemon) ob(name string) *observed {
	o := d.obs[name]
	if o == nil {
		o = &observed{}
		d.obs[name] = o
	}
	return o
}

// startFamily gives one family's clients on name a fresh context.
func (d *Daemon) startFamily(parent context.Context, name string, v6 bool) context.Context {
	ctx, cancel := context.WithCancel(parent)
	d.mu.Lock()
	defer d.mu.Unlock()
	o := d.ob(name)
	if v6 {
		o.ctx6, o.stop6, o.lease6, o.ra, o.info = ctx, cancel, nil, nil, false
	} else {
		o.ctx4, o.stop4, o.lease4 = ctx, cancel, nil
	}
	return ctx
}

// stopIface ends the clients of the chosen families on name and forgets
// what they learnt.
func (d *Daemon) stopIface(name string, v4, v6 bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	o := d.obs[name]
	if o == nil {
		return
	}
	if v4 && o.stop4 != nil {
		o.stop4()
		o.stop4, o.lease4 = nil, nil
	}
	if v6 && o.stop6 != nil {
		o.stop6()
		o.stop6, o.lease6, o.ra, o.info = nil, nil, nil, false
	}
}

func (d *Daemon) stopAll() {
	d.mu.Lock()
	var names []string
	for n := range d.obs {
		names = append(names, n)
	}
	if d.ntpStop != nil {
		d.ntpStop()
	}
	for id, ch := range d.subs {
		close(ch)
		delete(d.subs, id)
	}
	d.mu.Unlock()
	for _, n := range names {
		d.stopIface(n, true, true)
	}
}

func (d *Daemon) onLease4(ctx context.Context, name string, metric uint32, l *Lease4) {
	d.applyMu.Lock()
	defer d.applyMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	sys, lg := d.o.Sys, d.o.Logger
	d.mu.Lock()
	o := d.ob(name)
	old := o.lease4
	o.lease4 = l
	d.mu.Unlock()
	if old != nil && (l == nil || old.Addr != l.Addr) {
		if err := sys.DelAddr(name, old.Addr); err != nil {
			lg.Error(err, "netd: the old DHCPv4 address wasn't removed", log.F("iface", name))
		}
	}
	if l == nil {
		lg.Warn("netd: DHCPv4 lease lost", log.F("iface", name))
		if err := sys.DelDefaultRoute(name, false, metric); err != nil {
			lg.Error(err, "netd: the DHCPv4 default route wasn't removed", log.F("iface", name))
		}
	} else {
		secs := uint32(min(l.Lease/time.Second, netlink.Forever-1)) // #nosec G115 -- clamped
		if err := sys.AddAddr(name, l.Addr, secs, secs); err != nil {
			lg.Error(err, "netd: the DHCPv4 address wasn't added", log.F("iface", name), log.F("addr", l.Addr.String()))
		}
		if l.Router.IsValid() {
			if err := sys.ReplaceDefaultRoute(name, l.Router, metric, netlink.ProtoDHCP); err != nil {
				lg.Error(err, "netd: the DHCPv4 default route wasn't set", log.F("iface", name))
			}
		}
		lg.Info("netd: DHCPv4 address bound", log.F("iface", name), log.F("address", l.Addr.String()), log.F("router", l.Router.String()), log.F("lease", l.Lease.String()))
	}
	if err := d.refresh(); err != nil {
		lg.Error(err, "netd: refresh after a DHCPv4 lease")
	}
}

func (d *Daemon) onLease6(ctx context.Context, name string, l *Lease6) {
	d.applyMu.Lock()
	defer d.applyMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	sys, lg := d.o.Sys, d.o.Logger
	d.mu.Lock()
	o := d.ob(name)
	old := o.lease6
	o.lease6 = l
	d.mu.Unlock()
	if old != nil && old.Addr.IsValid() && (l == nil || old.Addr != l.Addr) {
		if err := sys.DelAddr(name, old.Addr); err != nil {
			lg.Error(err, "netd: the old DHCPv6 address wasn't removed", log.F("iface", name))
		}
	}
	if l != nil && l.Addr.IsValid() {
		valid := uint32(min(l.Valid/time.Second, netlink.Forever-1))         // #nosec G115 -- clamped
		preferred := uint32(min(l.Preferred/time.Second, netlink.Forever-1)) // #nosec G115 -- clamped
		if err := sys.AddAddr(name, l.Addr, valid, preferred); err != nil {
			lg.Error(err, "netd: the DHCPv6 address wasn't added", log.F("iface", name), log.F("addr", l.Addr.String()))
		}
		lg.Info("netd: DHCPv6 address bound", log.F("iface", name), log.F("address", l.Addr.String()))
	}
	if err := d.refresh(); err != nil {
		lg.Error(err, "netd: refresh after a DHCPv6 reply")
	}
}

func (d *Daemon) onRA(ctx context.Context, name string, _ uint32, ra *RAInfo) {
	d.mu.Lock()
	if ctx.Err() != nil {
		d.mu.Unlock()
		return
	}
	o := d.ob(name)
	o.ra = ra
	startInfo := ra != nil && ra.Other && !o.info && d.modeOf(name) == network.V6SLAAC
	if startInfo {
		o.info = true
	}
	d.mu.Unlock()
	if startInfo {
		d.o.Logger.Debug("netd: the router asks for stateless DHCPv6", log.F("iface", name))
		go d.o.Workers.DHCPv6(ctx, name, false, func(l *Lease6) { d.onLease6(ctx, name, l) })
	}
	if err := d.refresh(); err != nil {
		d.o.Logger.Error(err, "netd: refresh after a router advertisement")
	}
}

// modeOf is name's IPv6 mode; d.mu is held.
func (d *Daemon) modeOf(name string) network.Mode6 {
	for _, i := range d.applied {
		if i.Name == name {
			return i.IPv6.Mode
		}
	}
	return network.V6Off
}

// learnt is what DNS, search and NTP the clients gave, management first.
func (d *Daemon) learnt(s network.Settings) (dns []netip.Addr, search, ntp []string) {
	names := []string{s.Management.Name}
	if s.Service != nil {
		names = append(names, s.Service.Name)
	}
	for _, n := range names {
		o := d.obs[n]
		if o == nil {
			continue
		}
		if l := o.lease4; l != nil {
			dns = append(dns, l.DNS...)
			search = append(search, l.Search...)
			if l.Domain != "" {
				search = append(search, l.Domain)
			}
			ntp = append(ntp, l.NTP...)
		}
		if l := o.lease6; l != nil {
			dns = append(dns, l.DNS...)
			search = append(search, l.Search...)
			ntp = append(ntp, l.NTP...)
		}
		if r := o.ra; r != nil {
			dns = append(dns, r.RDNSS...)
			search = append(search, r.Search...)
		}
	}
	return uniq(dns), uniq(search), uniq(ntp)
}

func uniq[T comparable](in []T) []T {
	var out []T
	for _, v := range in {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// effective is what the resolver, the clock and the host name use: the
// settings where they say something, what DHCP and RA offer otherwise.
func (d *Daemon) effective() (s network.Settings, dns []netip.Addr, search, ntp []string, src timesync.Source, host string) {
	s = d.settings
	ldns, lsearch, lntp := d.learnt(s)
	dns, search, ntp = s.DNS, s.Search, s.NTP
	src = timesync.SourceSettings
	if len(dns) == 0 {
		dns = ldns
	}
	if len(search) == 0 {
		search = lsearch
	}
	if len(ntp) == 0 {
		ntp, src = lntp, timesync.SourceDHCP
	}
	if len(ntp) > network.MaxNTP {
		ntp = ntp[:network.MaxNTP]
	}
	if len(ntp) == 0 {
		src = timesync.SourceNone
	}
	host = s.Hostname
	if host == "" {
		if o := d.obs[s.Management.Name]; o != nil && o.lease4 != nil && o.lease4.Hostname != "" {
			host = o.lease4.Hostname
			if !strings.Contains(host, ".") && o.lease4.Domain != "" {
				host += "." + o.lease4.Domain
			}
		}
	}
	return s, dns, search, ntp, src, host
}

// refresh brings everything that follows the settings and the clients'
// results up to date: resolv.conf, the host name, the NTP engine, the
// firewall, and the address event.
func (d *Daemon) refresh() error {
	lg := d.o.Logger
	d.mu.Lock()
	s, dns, search, ntp, src, host := d.effective()
	tbl := d.tableLocked(s)
	ctx := d.ctx
	var errs []error
	resolv := string(network.RenderResolv(dns, search))
	if resolv != d.resolv {
		if err := writeAtomic(filepath.Join(d.o.RunDir, "resolv.conf"), []byte(resolv), 0o644); err != nil {
			errs = append(errs, err)
		} else {
			d.resolv = resolv
			lg.Info("netd: resolv.conf written", log.F("servers", len(dns)), log.F("search", len(search)))
		}
	}
	kname := host
	if kname == "" {
		kname = d.o.Fallback
	}
	if kname != "" && kname != d.kernel {
		if err := d.o.Sys.SetHostname(kname); err != nil {
			errs = append(errs, err)
		} else {
			d.kernel = kname
			lg.Info("netd: host name set", log.F("hostname", kname), log.F("own_name", host == ""))
		}
	}
	if host != "" && host == d.kernel {
		d.hostname = host
	}
	key := fmt.Sprint(src, ntp)
	if d.ntp == nil || key != d.ntpKey {
		if d.ntpStop != nil {
			d.ntpStop()
		}
		eng := d.o.NewTimeSync(ntp, src)
		d.ntp, d.ntpKey = eng, key
		if ctx != nil {
			nctx, cancel := context.WithCancel(ctx)
			d.ntpStop = cancel
			go func() {
				eng.BootSync(nctx)
				eng.Run(nctx)
			}()
		}
		lg.Info("netd: time servers set", log.F("servers", strings.Join(ntp, ",")), log.F("source", src.String()))
	}
	if !d.noNIC && (d.table == nil || !reflect.DeepEqual(*d.table, tbl)) {
		if err := d.o.Sys.Firewall(tbl); err != nil {
			errs = append(errs, fmt.Errorf("netd: firewall: %w", err))
		} else {
			d.table = &tbl
			lg.Info("netd: firewall written", log.F("iface", tbl.MgmtIf), log.F("ssh", tbl.Open22), log.F("https", tbl.Open8443), log.F("allowV4", len(tbl.AllowV4)), log.F("allowV6", len(tbl.AllowV6)))
		}
	}
	d.mu.Unlock()
	d.publish()
	return errors.Join(errs...)
}

// tableLocked is the firewall for s; d.mu is held.
func (d *Daemon) tableLocked(s network.Settings) firewall.Table {
	done := d.setupDone()
	t := firewall.Table{MgmtIf: s.Management.Name, Open22: d.ports.SSH || done, Open8443: d.ports.HTTPS || done}
	for _, p := range s.AllowList {
		if p.Addr().Is4() {
			t.AllowV4 = append(t.AllowV4, p)
		} else {
			t.AllowV6 = append(t.AllowV6, p)
		}
	}
	if len(d.service) > 0 {
		iface := s.Management.Name
		if s.Service != nil {
			iface = s.Service.Name
		}
		sp := &firewall.ServicePorts{Iface: iface}
		for _, r := range d.service {
			pr := firewall.PortRule{Protocol: r.Protocol, Port: r.Port}
			for _, p := range r.Allow {
				if p.Addr().Is4() {
					pr.AllowV4 = append(pr.AllowV4, p)
				} else {
					pr.AllowV6 = append(pr.AllowV6, p)
				}
			}
			sp.Rules = append(sp.Rules, pr)
		}
		t.Service = sp
	}
	return t
}

// usable lists name's addresses a listener can bind: no link-local, none
// still in DAD or failed it.
func (d *Daemon) usable(name string) []string {
	if name == "" {
		return nil
	}
	addrs, err := d.o.Sys.Addrs(name)
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		if a.Prefix.Addr().IsLinkLocalUnicast() || a.Tentative() || a.DADFailed() || a.Scope != 0 && a.Scope != 200 {
			continue
		}
		out = append(out, a.Prefix.String())
	}
	sort.Strings(out)
	return out
}

func (d *Daemon) addresses() Addresses {
	d.mu.Lock()
	s, host := d.settings, d.hostname
	d.mu.Unlock()
	a := Addresses{Management: d.usable(s.Management.Name), Hostname: host}
	if s.Service != nil {
		a.Service = d.usable(s.Service.Name)
	}
	return a
}

// publish sends the addresses to every watcher when they changed.
func (d *Daemon) publish() {
	a := d.addresses()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.haveLast && reflect.DeepEqual(a, d.last) {
		return
	}
	d.last, d.haveLast = a, true
	d.o.Logger.Info("netd: management addresses", log.F("addresses", strings.Join(a.Management, ",")), log.F("service", strings.Join(a.Service, ",")))
	for _, ch := range d.subs {
		send(ch, a)
	}
}

// send replaces whatever the watcher hasn't read yet with a.
func send(ch chan Addresses, a Addresses) {
	select {
	case <-ch:
	default:
	}
	ch <- a
}

// Watch returns the addresses now and on every change, until stop.
func (d *Daemon) Watch() (<-chan Addresses, func()) {
	ch := make(chan Addresses, 1)
	a := d.addresses()
	d.mu.Lock()
	id := d.nextSub
	d.nextSub++
	d.subs[id] = ch
	send(ch, a)
	d.mu.Unlock()
	return ch, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if _, ok := d.subs[id]; ok {
			delete(d.subs, id)
			close(ch)
		}
	}
}

func (d *Daemon) watchKernel(ctx context.Context, notices <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-notices:
			if !ok {
				return
			}
		}
		d.mu.Lock()
		waiting := d.noNIC
		d.mu.Unlock()
		if waiting {
			if nic, err := d.firstNIC(); err == nil && nic != "" {
				d.o.Logger.Info("netd: an interface appeared; running the defaults on it", log.F("nic", nic))
				if err := d.applyAndSave(network.Defaults(nic), false); err != nil {
					d.o.Logger.Error(err, "netd: the defaults didn't apply fully")
				}
				continue
			}
		}
		d.publish()
	}
}

// Status is the live state.
func (d *Daemon) Status() Status {
	a := d.addresses()
	d.mu.Lock()
	defer d.mu.Unlock()
	st := Status{Management: a.Management, Service: a.Service, Hostname: a.Hostname}
	if d.table != nil {
		st.SSHOpen, st.HTTPSOpen = d.table.Open22, d.table.Open8443
	}
	if d.ntp != nil {
		ts := d.ntp.Status()
		st.NTPSynced = ts.State == timesync.StateSynced
		if ts.HasOffset {
			st.NTPOffset = ts.LastOffset
		}
	}
	return st
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- /run/sneakers, read by every service
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
