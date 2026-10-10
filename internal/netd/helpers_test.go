// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/clock"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/firewall"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netlink"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/timesync"
)

// fakeSys is the box's kernel as netd sees it: links, addresses and
// routes in memory, and a record of what netd asked for.
type fakeSys struct {
	mu        sync.Mutex
	links     []netd.Link
	addrs     map[string][]netlink.Addr
	routes    map[string][]netlink.Route
	ipv6      map[string]network.Mode6
	hostname  string
	tables    []firewall.Table
	up        []string
	reachErr  error
	dnsErr    map[netip.Addr]error
	dnsAsked  []string
	notices   chan struct{}
	subscribe int
}

func newFakeSys(links ...netd.Link) *fakeSys {
	return &fakeSys{links: links, addrs: map[string][]netlink.Addr{}, routes: map[string][]netlink.Route{},
		ipv6: map[string]network.Mode6{}, dnsErr: map[netip.Addr]error{}, notices: make(chan struct{}, 16)}
}

func (f *fakeSys) Links() ([]netd.Link, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.links), nil
}

func (f *fakeSys) LinkUp(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.up = append(f.up, name)
	return nil
}

func (f *fakeSys) Addrs(name string) ([]netlink.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.addrs[name]), nil
}

func (f *fakeSys) AddAddr(name string, p netip.Prefix, valid, preferred uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs[name] = slices.DeleteFunc(f.addrs[name], func(a netlink.Addr) bool { return a.Prefix == p })
	flags := uint32(0)
	if valid == netlink.Forever {
		flags = netlink.FlagPermanent
	}
	f.addrs[name] = append(f.addrs[name], netlink.Addr{Prefix: p, Valid: valid, Preferred: preferred, Flags: flags})
	return nil
}

func (f *fakeSys) DelAddr(name string, p netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs[name] = slices.DeleteFunc(f.addrs[name], func(a netlink.Addr) bool { return a.Prefix == p })
	return nil
}

func (f *fakeSys) ReplaceDefaultRoute(name string, gw netip.Addr, metric uint32, proto byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	v6 := gw.Is6()
	f.routes[name] = slices.DeleteFunc(f.routes[name], func(r netlink.Route) bool { return r.Default() && r.Gateway.Is6() == v6 && r.Metric == metric })
	f.routes[name] = append(f.routes[name], netlink.Route{Dst: netip.PrefixFrom(unspec(v6), 0), Gateway: gw, Metric: metric, Protocol: proto})
	return nil
}

func (f *fakeSys) DelDefaultRoute(name string, v6 bool, metric uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[name] = slices.DeleteFunc(f.routes[name], func(r netlink.Route) bool { return r.Default() && r.Gateway.Is6() == v6 && r.Metric == metric })
	return nil
}

func unspec(v6 bool) netip.Addr {
	if v6 {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}

func (f *fakeSys) Routes(name string) ([]netlink.Route, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.routes[name]), nil
}

func (f *fakeSys) SetIPv6(name string, m network.Mode6) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ipv6[name] = m
	return nil
}

func (f *fakeSys) SetHostname(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hostname = name
	return nil
}

func (f *fakeSys) Firewall(t firewall.Table) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tables = append(f.tables, t)
	return nil
}

func (f *fakeSys) Reach(context.Context, string, netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reachErr
}

func (f *fakeSys) QueryDNS(_ context.Context, server netip.Addr, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dnsAsked = append(f.dnsAsked, server.String()+" "+name)
	return f.dnsErr[server]
}

func (f *fakeSys) Subscribe(ctx context.Context) (<-chan struct{}, error) {
	f.mu.Lock()
	f.subscribe++
	f.mu.Unlock()
	return f.notices, nil
}

// kernelAddr puts an address on name as the kernel would (SLAAC, or one
// left from before), and tells netd.
func (f *fakeSys) kernelAddr(name, p string, flags uint32) {
	f.mu.Lock()
	f.addrs[name] = append(f.addrs[name], netlink.Addr{Prefix: netip.MustParsePrefix(p), Flags: flags, Valid: 3600, Preferred: 1800})
	f.mu.Unlock()
	f.notices <- struct{}{}
}

func (f *fakeSys) lastTable() firewall.Table {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.tables) == 0 {
		return firewall.Table{}
	}
	return f.tables[len(f.tables)-1]
}

func (f *fakeSys) prefixes(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, a := range f.addrs[name] {
		out = append(out, a.Prefix.String())
	}
	slices.Sort(out)
	return out
}

// fakeWorkers stands in for the DHCP and RA clients: a test hands netd a
// lease or an advertisement by calling the report it was given.
type fakeWorkers struct {
	mu      sync.Mutex
	started []string
	r4      map[string]func(*netd.Lease4)
	r6      map[string]func(*netd.Lease6)
	ra      map[string]func(*netd.RAInfo)
	live    map[string]context.Context
}

func newFakeWorkers() *fakeWorkers {
	return &fakeWorkers{r4: map[string]func(*netd.Lease4){}, r6: map[string]func(*netd.Lease6){}, ra: map[string]func(*netd.RAInfo){}, live: map[string]context.Context{}}
}

func (w *fakeWorkers) DHCPv4(ctx context.Context, iface string, report func(*netd.Lease4)) {
	w.mu.Lock()
	w.started = append(w.started, "dhcpv4 "+iface)
	w.r4[iface] = report
	w.live["dhcpv4 "+iface] = ctx
	w.mu.Unlock()
	<-ctx.Done()
}

func (w *fakeWorkers) DHCPv6(ctx context.Context, iface string, stateful bool, report func(*netd.Lease6)) {
	kind := "dhcpv6-info "
	if stateful {
		kind = "dhcpv6 "
	}
	w.mu.Lock()
	w.started = append(w.started, kind+iface)
	w.r6[iface] = report
	w.live[kind+iface] = ctx
	w.mu.Unlock()
	<-ctx.Done()
}

func (w *fakeWorkers) RA(ctx context.Context, iface string, report func(*netd.RAInfo)) {
	w.mu.Lock()
	w.started = append(w.started, "ra "+iface)
	w.ra[iface] = report
	w.live["ra "+iface] = ctx
	w.mu.Unlock()
	<-ctx.Done()
}

func (w *fakeWorkers) running(t *testing.T) []string {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for k, ctx := range w.live {
		if ctx.Err() == nil {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// waitStarted waits until each named worker ("ra eth0", say) has started:
// the daemon starts each in its own goroutine, so one may not have run yet
// when the test goes on.
func (w *fakeWorkers) waitStarted(t *testing.T, names ...string) {
	t.Helper()
	waitFor(t, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		for _, n := range names {
			if !slices.Contains(w.started, n) {
				return false
			}
		}
		return true
	})
}

func (w *fakeWorkers) report4(t *testing.T, iface string, l *netd.Lease4) {
	t.Helper()
	waitFor(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.r4[iface] != nil })
	w.mu.Lock()
	r := w.r4[iface]
	w.mu.Unlock()
	r(l)
}

func (w *fakeWorkers) report6(t *testing.T, iface string, l *netd.Lease6) {
	t.Helper()
	waitFor(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.r6[iface] != nil })
	w.mu.Lock()
	r := w.r6[iface]
	w.mu.Unlock()
	r(l)
}

func (w *fakeWorkers) reportRA(t *testing.T, iface string, ra *netd.RAInfo) {
	t.Helper()
	waitFor(t, func() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.ra[iface] != nil })
	w.mu.Lock()
	r := w.ra[iface]
	w.mu.Unlock()
	r(ra)
}

// fakeTime records the NTP servers netd hands the engine.
type fakeTime struct {
	mu      sync.Mutex
	servers []string
	source  timesync.Source
	status  timesync.Status
	made    int
}

func (f *fakeTime) New(servers []string, src timesync.Source) netd.TimeSync {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.servers, f.source = slices.Clone(servers), src
	f.made++
	if f.status.State == timesync.StateNotConfigured && len(servers) > 0 {
		f.status.State = timesync.StateSynced
		f.status.HasOffset = true
		f.status.LastOffset = 12 * time.Millisecond
	}
	return fakeEngine{f}
}

type fakeEngine struct{ f *fakeTime }

func (e fakeEngine) BootSync(context.Context) {}
func (e fakeEngine) Run(ctx context.Context)  { <-ctx.Done() }
func (e fakeEngine) SyncNow(context.Context)  {}
func (e fakeEngine) Status() timesync.Status {
	e.f.mu.Lock()
	defer e.f.mu.Unlock()
	st := e.f.status
	st.Servers = slices.Clone(e.f.servers)
	return st
}

func (f *fakeTime) get() ([]string, timesync.Source) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.servers), f.source
}

type box struct {
	t       *testing.T
	state   string
	run     string
	sys     *fakeSys
	workers *fakeWorkers
	time    *fakeTime
	clk     *clock.Fake
	// fallback is the box's own name (Options.Fallback).
	fallback string
	// offered is the host name the deployment offers (Options.Offered).
	offered func() string
	// audit and logger, when set, are netd's audit log and logger.
	audit  osaudit.Appender
	logger log.Logger
	d      *netd.Daemon
	cancel context.CancelFunc
}

var (
	eth0 = netd.Link{Name: "eth0", MAC: "52:54:00:00:00:01", Up: true, Driver: "virtio_net", Bus: "pci0000:00/0000:00:03.0/virtio0"}
	eth1 = netd.Link{Name: "eth1", MAC: "52:54:00:00:00:02", Up: true, Driver: "virtio_net", Bus: "pci0000:00/0000:00:04.0/virtio1"}
)

func newBox(t *testing.T, links ...netd.Link) *box {
	t.Helper()
	if len(links) == 0 {
		links = []netd.Link{eth0}
	}
	return &box{t: t, state: t.TempDir(), run: t.TempDir(), sys: newFakeSys(links...), workers: newFakeWorkers(), time: &fakeTime{}, clk: clock.NewFake()}
}

func (b *box) start() *netd.Daemon {
	b.t.Helper()
	d, err := netd.New(netd.Options{StateDir: b.state, RunDir: b.run, Sys: b.sys, Workers: b.workers, NewTimeSync: b.time.New, Clock: b.clk, Fallback: b.fallback, Offered: b.offered, Audit: b.audit, Logger: b.logger})
	if err != nil {
		b.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := d.Start(ctx); err != nil {
		cancel()
		b.t.Fatal(err)
	}
	b.t.Cleanup(cancel)
	b.d, b.cancel = d, cancel
	return d
}

func (b *box) writeSettings(name string, s network.Settings) {
	b.t.Helper()
	if err := network.WriteFile(filepath.Join(b.state, "settings", name), s); err != nil {
		b.t.Fatal(err)
	}
}

func (b *box) read(rel string) string {
	b.t.Helper()
	data, err := os.ReadFile(filepath.Join(b.run, rel))
	if err != nil {
		b.t.Fatal(err)
	}
	return string(data)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition never held")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func static(nic string) network.Settings {
	s := network.Defaults(nic)
	s.Management.IPv4 = network.Family4{Mode: network.V4Static, Address: netip.MustParsePrefix("192.0.2.10/24"), Gateway: netip.MustParseAddr("192.0.2.1")}
	s.Management.IPv6 = network.Family6{Mode: network.V6Static, Address: netip.MustParsePrefix("2001:db8::10/64"), Gateway: netip.MustParseAddr("fe80::1")}
	s.Hostname = "appliance.sneakers.example.org"
	s.DNS = []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("2001:db8::53")}
	s.Search = []string{"sneakers.example.org"}
	s.NTP = []string{"192.0.2.123", "time.example.org"}
	return s
}

var errDown = errors.New("no answer")
