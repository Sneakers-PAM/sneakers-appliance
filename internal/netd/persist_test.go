// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netd_test

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/netd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/network"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// restart stops the running netd and starts a new one on the same state
// volume, the way a reboot, a base update (the other slot's netd) or a
// revert does: the kernel comes back empty, only the state volume stays.
func (b *box) restart() *netd.Daemon {
	b.t.Helper()
	b.cancel()
	b.sys = newFakeSys(b.sys.links...)
	b.workers = newFakeWorkers()
	b.time = &fakeTime{}
	return b.start()
}

// dnsAndNTP is a DHCP box with the DNS servers, search domain and NTP
// host an admin typed on the Network page.
func dnsAndNTP(nic string) network.Settings {
	s := network.Defaults(nic)
	s.DNS = []netip.Addr{netip.MustParseAddr("192.0.2.53")}
	s.Search = []string{"sneakers.example.org"}
	s.NTP = []string{"time.example.org"}
	return s
}

func keeps(t *testing.T, d *netd.Daemon, when string) {
	t.Helper()
	s, pending := d.Get()
	if pending {
		t.Fatalf("%s: a change is pending", when)
	}
	if !slices.Equal(s.DNS, []netip.Addr{netip.MustParseAddr("192.0.2.53")}) || !slices.Equal(s.Search, []string{"sneakers.example.org"}) || !slices.Equal(s.NTP, []string{"time.example.org"}) {
		t.Fatalf("%s: dns %v search %v ntp %v", when, s.DNS, s.Search, s.NTP)
	}
}

// A confirmed DNS and NTP change is kept across a reboot, a base update and
// a revert: each is a new netd on the same state volume.
func TestAConfirmedChangeIsKeptAcrossRestarts(t *testing.T) {
	b := newBox(t)
	d := b.start()
	next := dnsAndNTP("eth0")
	next.AllowList = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	tok, err := d.Set(next)
	if err != nil || tok == "" {
		t.Fatalf("token %q, %v", tok, err)
	}
	if err := d.Confirm(tok); err != nil {
		t.Fatal(err)
	}
	keeps(t, d, "after the confirm")
	for _, when := range []string{"the reboot", "the base update", "the revert", "a second reboot"} {
		d = b.restart()
		keeps(t, d, "after "+when)
		if servers, _ := b.time.get(); !slices.Equal(servers, []string{"time.example.org"}) {
			t.Fatalf("after %s the NTP engine has %v", when, servers)
		}
		if got := b.read("resolv.conf"); got != "# Written by sneakers-netd.\nnameserver 192.0.2.53\nsearch sneakers.example.org\n" {
			t.Fatalf("after %s resolv.conf:\n%s", when, got)
		}
	}
}

// A change that can't move the box off the network (DNS, search, NTP, the
// time zone, the proxy) has nothing to heal: it's kept at once, with no
// window, so it never reverts because nobody clicked Confirm, and a
// reboot right after it keeps it.
func TestADNSAndNTPChangeIsKeptWithoutAWindow(t *testing.T) {
	b := newBox(t)
	d := b.start()
	tok, err := d.Set(dnsAndNTP("eth0"))
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		t.Fatalf("a DNS and NTP change waits for a confirmation (token %q)", tok)
	}
	keeps(t, d, "right after the change")
	if _, err := os.Stat(filepath.Join(b.state, "settings", "network.prev.yaml")); !os.IsNotExist(err) {
		t.Fatalf("network.prev.yaml after a change with no window: %v", err)
	}
	keeps(t, b.restart(), "after a reboot right after the change")
}

// A change that moves the address still waits, and a reboot inside its
// window undoes it, and says so: the next netd reports the change as
// reverted at start.
func TestAnUnconfirmedChangeUndoneAtStartIsReported(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	next := static("eth0")
	next.Management.IPv4.Address = netip.MustParsePrefix("192.0.2.20/24")
	if tok, err := d.Set(next); err != nil || tok == "" {
		t.Fatalf("token %q, %v", tok, err)
	}
	d = b.restart()
	if s, _ := d.Get(); s.Management.IPv4.Address.String() != "192.0.2.10/24" {
		t.Fatalf("settings %v", s.Management.IPv4.Address)
	}
	last, ok := d.LastChange()
	if !ok || !last.Reverted || !last.AtStart {
		t.Fatalf("last change %+v %v", last, ok)
	}
	// The confirmed settings from before the change are kept from then on.
	if s, _ := b.restart().Get(); s.Management.IPv4.Address.String() != "192.0.2.10/24" {
		t.Fatalf("after another reboot %v", s.Management.IPv4.Address)
	}
}

// A confirmation only counts once network.prev.yaml is gone: if it can't
// be removed, Confirm fails, so the page never says "Confirmed" for a
// change the next start would undo.
func TestAConfirmThatCantDropTheUndoFileFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory's mode")
	}
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	next := static("eth0")
	next.Management.IPv4.Address = netip.MustParsePrefix("192.0.2.20/24")
	tok, err := d.Set(next)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(b.state, "settings")
	if err := os.Chmod(dir, 0o500); err != nil { // #nosec G302 -- a test directory
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- as above
	if err := d.Confirm(tok); err == nil {
		t.Fatal("Confirm succeeded with network.prev.yaml still there")
	}
	if _, pending := d.Get(); !pending {
		t.Fatal("the change isn't pending any more")
	}
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- as above
		t.Fatal(err)
	}
	if err := d.Confirm(tok); err != nil {
		t.Fatalf("the second Confirm: %v", err)
	}
	if s, _ := b.restart().Get(); s.Management.IPv4.Address.String() != "192.0.2.20/24" {
		t.Fatalf("the confirmed change was dropped at start: %v", s.Management.IPv4.Address)
	}
}

// A change to DNS while another one waits joins that one's window: it can't
// be kept on its own while the undo file names older settings.
func TestASafeChangeWhileOneIsPendingIsRefused(t *testing.T) {
	b := newBox(t)
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	next := static("eth0")
	next.Management.IPv4.Address = netip.MustParsePrefix("192.0.2.20/24")
	if _, err := d.Set(next); err != nil {
		t.Fatal(err)
	}
	dns := next
	dns.DNS = []netip.Addr{netip.MustParseAddr("192.0.2.54")}
	if _, err := d.Set(dns); !codes.Is(err, codes.NetInvalid) || network.Field(err) != "pending" {
		t.Fatalf("err %v", err)
	}
}

type auditLog struct {
	mu      sync.Mutex
	entries []osaudit.Entry
}

func (a *auditLog) Append(e osaudit.Entry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

// A change nobody confirmed is undone, by its window or at start when the
// box restarted inside it, and both say so at error level, which reaches
// a production box's log; the start-time undo is audited by netd.
func TestAnUnconfirmedChangeIsUndoneLoudly(t *testing.T) {
	var buf syncBuffer
	b := newBox(t)
	b.logger = log.NewLoggerWithOptions("sneakers-netd", log.WithOutput(&buf), log.WithDefaultFormat(log.FormatJSON), log.WithDefaultLevel(log.LevelError))
	a := &auditLog{}
	b.audit = a
	b.writeSettings("network.yaml", static("eth0"))
	d := b.start()
	next := static("eth0")
	next.AllowList = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	if _, err := d.Set(next); err != nil {
		t.Fatal(err)
	}
	b.clk.Advance(121 * time.Second)
	if s, _ := d.Get(); len(s.AllowList) != 0 {
		t.Fatalf("not undone: %v", s.AllowList)
	}
	if !strings.Contains(buf.String(), "wasn't confirmed") {
		t.Fatalf("the window's revert isn't logged at error level:\n%s", buf.String())
	}

	buf.Reset()
	if _, err := d.Set(next); err != nil {
		t.Fatal(err)
	}
	d = b.restart()
	if s, _ := d.Get(); len(s.AllowList) != 0 {
		t.Fatalf("not undone at start: %v", s.AllowList)
	}
	if !strings.Contains(buf.String(), "undone at start") {
		t.Fatalf("the start-time undo isn't logged at error level:\n%s", buf.String())
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.entries) != 1 {
		t.Fatalf("audit %+v", a.entries)
	}
	if e := a.entries[0]; e.Action != "network.revert" || e.Actor != "netd" || e.Outcome != "refused" || e.Code != "NET_REVERTED" || e.Detail["at"] != "start" || e.Detail["change"] == "" {
		t.Fatalf("audit %+v", e)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}
