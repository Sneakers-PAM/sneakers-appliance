// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netd_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"
	log "github.com/Bugs5382/go-log"

	netdv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/netd/v1/netdv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netdapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testutil/netns"
)

func TestMain(m *testing.M) {
	netns.RunHelpers(map[string]func() error{"router": netns.RouterHelper, "box": boxHelper, "links": linksHelper})
	os.Exit(m.Run())
}

// labSys is the real Linux system with the host name kept in the process:
// ip netns exec shares the host's UTS namespace, and the test must never
// rename the machine it runs on.
type labSys struct {
	netd.Linux
	mu   sync.Mutex
	host string
}

// Links marks the lab's eth* veth ends as the box's NICs: a veth has no
// bus, and netd only takes NICs that do.
func (l *labSys) Links() ([]netd.Link, error) {
	links, err := l.Linux.Links()
	for i := range links {
		if strings.HasPrefix(links[i].Name, "eth") {
			links[i].Bus = "lab/" + links[i].Name
		}
	}
	return links, err
}

func (l *labSys) SetHostname(name string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.host = name
	return nil
}

// labClock reads the real clock and never sets it: the host's clock isn't
// namespaced either.
type labClock struct{}

func (labClock) Now() time.Time                 { return time.Now() }
func (labClock) Step(time.Duration) error       { return nil }
func (labClock) Slew(time.Duration) error       { return nil }
func (labClock) MarkSynced(time.Duration) error { return nil }

// boxHelper runs the real netd (netlink, sysctls, nftables, the DHCP and
// RA clients) inside the box namespace, on the socket in BOX_DIR.
func boxHelper() error {
	dir := os.Getenv("BOX_DIR")
	var s network.Settings
	if err := json.Unmarshal([]byte(os.Getenv("BOX_SETTINGS")), &s); err != nil {
		return err
	}
	state, run := filepath.Join(dir, "state"), filepath.Join(dir, "run")
	if err := network.WriteFile(filepath.Join(state, "settings", "network.yaml"), s); err != nil {
		return err
	}
	lg := log.NewLoggerWithOptions("sneakers-netd", log.WithOutput(os.Stderr), log.WithDefaultFormat(log.FormatConsole), log.WithDefaultLevel(log.LevelDebug))
	d, err := netd.New(netd.Options{
		StateDir: state, RunDir: run, Sys: &labSys{}, Workers: netd.Clients{Logger: lg},
		NewTimeSync: netd.TimeSyncs(labClock{}, filepath.Join(state, "netd", "clock-floor"), time.Now().Add(-time.Hour), lg),
		Logger:      lg,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := d.Start(ctx); err != nil {
		return err
	}
	srv, err := netd.Listen(filepath.Join(dir, "netd.sock"), d, lg)
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()
	<-ctx.Done()
	return nil
}

// linksHelper prints the namespace's interfaces as the real Linux system
// reads them.
func linksHelper() error {
	links, err := netd.Linux{}.Links()
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(links)
}

// The interfaces k0s and the CNI make have no bus, so netd never takes
// one for the management interface.
func TestVirtualInterfacesHaveNoBus(t *testing.T) {
	l := netns.New(t)
	b, r := l.NS("b"), l.NS("r")
	l.Link(b, "eth0", r, "lan0")
	l.IP(b, "link", "add", "dummy0", "type", "dummy")
	l.IP(b, "link", "add", "cni0", "type", "bridge")
	l.IP(b, "link", "add", "kube-bridge", "type", "bridge")
	l.IP(b, "link", "add", "veth1a2b", "type", "veth", "peer", "name", "veth1a2c")
	for _, n := range []string{"dummy0", "cni0", "kube-bridge", "veth1a2b", "veth1a2c"} {
		l.IP(b, "link", "set", n, "up")
	}
	out, err := l.Run(b, "links")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var links []netd.Link
	if err := json.Unmarshal([]byte(out), &links); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	seen := map[string]bool{}
	for _, k := range links {
		seen[k.Name] = true
		if k.Physical() {
			t.Errorf("%s has a bus %q", k.Name, k.Bus)
		}
	}
	for _, n := range []string{"lo", "eth0", "dummy0", "cni0", "kube-bridge", "veth1a2b", "veth1a2c"} {
		if !seen[n] {
			t.Errorf("%s isn't listed: %v", n, links)
		}
	}
}

type netdLab struct {
	lab      *netns.Lab
	box, rtr string
	dir      string
	box1     *netns.Helper
}

// newNetdLab joins the box's eth0 to the router's lan0, which holds
// 192.0.2.1/24 and 2001:db8:1::1/64.
func newNetdLab(t *testing.T) *netdLab {
	l := netns.New(t)
	// A unix socket's path must stay under 108 bytes, which a test's temp
	// directory can pass.
	dir, err := os.MkdirTemp("/tmp", "netd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	n := &netdLab{lab: l, box: l.NS("b"), rtr: l.NS("r"), dir: dir}
	l.Link(n.box, "eth0", n.rtr, "lan0")
	l.IP(n.rtr, "addr", "add", "192.0.2.1/24", "dev", "lan0")
	l.IP(n.rtr, "addr", "add", "2001:db8:1::1/64", "dev", "lan0", "nodad")
	l.Sysctl(n.rtr, "net.ipv6.conf.all.forwarding", "1")
	return n
}

func (n *netdLab) router(t *testing.T, r netns.Router) {
	t.Helper()
	r.Iface = "lan0"
	h := n.lab.Start(n.rtr, "router", r.Env())
	waitOutput(t, h, "router ready")
}

func (n *netdLab) start(t *testing.T, s network.Settings) {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	n.box1 = n.lab.Start(n.box, "box", "BOX_DIR="+n.dir, "BOX_SETTINGS="+string(b))
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(n.dir, "netd.sock")); err == nil {
			return
		}
		if n.box1.Exited() || time.Now().After(deadline) {
			t.Fatalf("netd didn't start (%v):\n%s", n.box1.Err(), n.box1.Output())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (n *netdLab) client() netdv1connect.NetworkServiceClient {
	return netdapi.NewClient(filepath.Join(n.dir, "netd.sock"))
}

func waitOutput(t *testing.T, h *netns.Helper, s string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(h.Output(), s) {
		if h.Exited() || time.Now().After(deadline) {
			t.Fatalf("helper never printed %q:\n%s", s, h.Output())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitAddr waits until a management address inside want shows.
func (n *netdLab) waitAddr(t *testing.T, want ...string) []string {
	t.Helper()
	c := n.client()
	deadline := time.Now().Add(45 * time.Second)
	for {
		st, err := c.Status(context.Background(), connect.NewRequest(&netdv1.StatusRequest{}))
		if err == nil {
			got := st.Msg.GetManagementAddresses()
			ok := true
			for _, w := range want {
				p := netip.MustParsePrefix(w)
				if !slices.ContainsFunc(got, func(a string) bool { ap, err := netip.ParsePrefix(a); return err == nil && p.Contains(ap.Addr()) }) {
					ok = false
				}
			}
			if ok {
				return got
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no address in %v: status %v %v\nnetd:\n%s", want, st, err, n.box1.Output())
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func (n *netdLab) checksPass(t *testing.T, names ...string) {
	t.Helper()
	c := n.client()
	var last []*netdv1.Check
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		res, err := c.Checks(context.Background(), connect.NewRequest(&netdv1.ChecksRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		last = res.Msg.GetChecks()
		ok := true
		for _, name := range names {
			found := false
			for _, ch := range last {
				if ch.GetName() == name {
					found = true
					ok = ok && ch.GetState() == netdv1.CheckState_CHECK_STATE_OK
				}
			}
			ok = ok && found
		}
		if ok {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("checks %v didn't pass: %v\nnetd:\n%s", names, last, n.box1.Output())
}

func (n *netdLab) resolv(t *testing.T) string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(n.dir, "run", "resolv.conf"))
	return string(b)
}

func mode(v4 network.Mode4, v6 network.Mode6) network.Settings {
	s := network.Defaults("eth0")
	s.Management.IPv4.Mode, s.Management.IPv6.Mode = v4, v6
	return s
}

func TestNetdDHCPv4AgainstARealServer(t *testing.T) {
	n := newNetdLab(t)
	n.router(t, netns.Router{V4Lease: "192.0.2.100/24", V4Router: "192.0.2.1", DNS: "192.0.2.1", NTP: "192.0.2.1", Listen: []string{"192.0.2.1"}})
	n.start(t, mode(network.V4DHCP, network.V6Off))
	n.waitAddr(t, "192.0.2.100/32")
	n.checksPass(t, "link", "address", "gateway", "dns", "ntp")
	if r := n.resolv(t); !strings.Contains(r, "nameserver 192.0.2.1") || !strings.Contains(r, "search sneakers.example.org") {
		t.Fatalf("resolv.conf:\n%s", r)
	}
	// An address that appears later is sent to every watcher.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := n.client().Watch(ctx, connect.NewRequest(&netdv1.WatchRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() || !slices.Contains(stream.Msg().GetManagementAddresses(), "192.0.2.100/24") {
		t.Fatalf("first event %v %v", stream.Msg(), stream.Err())
	}
	n.lab.IP(n.box, "addr", "add", "192.0.2.77/24", "dev", "eth0")
	for stream.Receive() {
		if slices.Contains(stream.Msg().GetManagementAddresses(), "192.0.2.77/24") {
			return
		}
	}
	t.Fatalf("no event for the new address: %v", stream.Err())
}

// IPv6 only: SLAAC from the router's advertisement, its RDNSS in
// resolv.conf, and NTP from the stateless DHCPv6 reply the O flag asks
// for.
func TestNetdSLAACWithRDNSSOnAnIPv6OnlyNetwork(t *testing.T) {
	n := newNetdLab(t)
	n.router(t, netns.Router{RAPrefix: "2001:db8:1::/64", RDNSS: "2001:db8:1::1", Other: true, NTP: "2001:db8:1::1", Listen: []string{"2001:db8:1::1"}})
	n.start(t, mode(network.V4Off, network.V6SLAAC))
	n.waitAddr(t, "2001:db8:1::/64")
	n.checksPass(t, "link", "address", "gateway", "dns", "ntp")
	if r := n.resolv(t); !strings.Contains(r, "nameserver 2001:db8:1::1") {
		t.Fatalf("resolv.conf:\n%s", r)
	}
}

func TestNetdStatefulDHCPv6(t *testing.T) {
	n := newNetdLab(t)
	n.router(t, netns.Router{RAPrefix: "2001:db8:1::/64", Managed: true, V6Lease: "2001:db8:1::100", DNS: "2001:db8:1::1", Listen: []string{"2001:db8:1::1"}})
	n.start(t, mode(network.V4Off, network.V6DHCPv6))
	got := n.waitAddr(t, "2001:db8:1::100/128")
	if !slices.Contains(got, "2001:db8:1::100/128") {
		t.Fatalf("addresses %v", got)
	}
	n.checksPass(t, "address", "dns")
	if r := n.resolv(t); !strings.Contains(r, "nameserver 2001:db8:1::1") {
		t.Fatalf("resolv.conf:\n%s", r)
	}
}

func TestNetdDualStack(t *testing.T) {
	n := newNetdLab(t)
	n.router(t, netns.Router{V4Lease: "192.0.2.100/24", V4Router: "192.0.2.1", DNS: "192.0.2.1", RAPrefix: "2001:db8:1::/64", RDNSS: "2001:db8:1::1", Listen: []string{"192.0.2.1", "2001:db8:1::1"}})
	n.start(t, mode(network.V4DHCP, network.V6SLAAC))
	n.waitAddr(t, "192.0.2.100/32", "2001:db8:1::/64")
	n.checksPass(t, "address", "gateway", "dns")
}

func TestNetdStatic(t *testing.T) {
	n := newNetdLab(t)
	n.router(t, netns.Router{Listen: []string{"192.0.2.1", "2001:db8:1::1"}})
	s := network.Defaults("eth0")
	s.Management.IPv4 = network.Family4{Mode: network.V4Static, Address: netip.MustParsePrefix("192.0.2.10/24"), Gateway: netip.MustParseAddr("192.0.2.1")}
	s.Management.IPv6 = network.Family6{Mode: network.V6Static, Address: netip.MustParsePrefix("2001:db8:1::10/64"), Gateway: netip.MustParseAddr("2001:db8:1::1")}
	s.DNS = []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8:1::1")}
	s.NTP = []string{"2001:db8:1::1"}
	n.start(t, s)
	n.waitAddr(t, "192.0.2.10/32", "2001:db8:1::10/128")
	n.checksPass(t, "link", "address", "gateway", "dns", "ntp")
	if out := n.lab.IP(n.box, "-6", "route", "show", "default"); !strings.Contains(out, "2001:db8:1::1") {
		t.Fatalf("IPv6 default route:\n%s", out)
	}
}
