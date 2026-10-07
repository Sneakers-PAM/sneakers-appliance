// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package firewall_test

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/firewall"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testutil/netns"
)

func TestMain(m *testing.M) {
	netns.RunHelpers(map[string]func() error{"box": boxHelper, "dial": dialHelper})
	os.Exit(m.Run())
}

// boxHelper writes the table from FW_TABLE and listens on 22, 8443 and
// 9000 until it's stopped.
func boxHelper() error {
	var t firewall.Table
	if err := json.Unmarshal([]byte(os.Getenv("FW_TABLE")), &t); err != nil {
		return err
	}
	if err := firewall.Apply(t); err != nil {
		return err
	}
	for _, p := range []int{22, 8443, 9000} {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
		if err != nil {
			return err
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}
	fmt.Println("ready")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	return nil
}

// dialHelper connects from DIAL_FROM to DIAL_TO on each of DIAL_PORTS and
// prints port=ok or port=closed.
func dialHelper() error {
	from := net.ParseIP(os.Getenv("DIAL_FROM"))
	d := net.Dialer{Timeout: 1500 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: from}}
	for _, p := range strings.Split(os.Getenv("DIAL_PORTS"), ",") {
		c, err := d.Dial("tcp", net.JoinHostPort(os.Getenv("DIAL_TO"), p))
		if err != nil {
			fmt.Printf("%s=closed\n", p)
			continue
		}
		_ = c.Close()
		fmt.Printf("%s=ok\n", p)
	}
	return nil
}

type fwLab struct {
	lab      *netns.Lab
	box, rtr string
}

func newFwLab(t *testing.T) *fwLab {
	l := netns.New(t)
	f := &fwLab{lab: l, box: l.NS("b"), rtr: l.NS("r")}
	l.Link(f.box, "mgmt0", f.rtr, "lan0")
	l.Link(f.box, "svc0", f.rtr, "svcr0")
	l.IP(f.box, "addr", "add", "192.0.2.10/24", "dev", "mgmt0")
	l.IP(f.box, "addr", "add", "2001:db8::10/64", "dev", "mgmt0", "nodad")
	l.IP(f.box, "addr", "add", "198.51.100.10/24", "dev", "svc0")
	for _, a := range []string{"192.0.2.50/24", "192.0.2.60/24"} {
		l.IP(f.rtr, "addr", "add", a, "dev", "lan0")
	}
	l.IP(f.rtr, "addr", "add", "2001:db8::50/64", "dev", "lan0", "nodad")
	l.IP(f.rtr, "addr", "add", "198.51.100.50/24", "dev", "svcr0")
	return f
}

func (f *fwLab) startBox(t *testing.T, tbl firewall.Table) {
	t.Helper()
	b, err := json.Marshal(tbl)
	if err != nil {
		t.Fatal(err)
	}
	h := f.lab.Start(f.box, "box", "FW_TABLE="+string(b))
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(h.Output(), "ready") {
		if h.Exited() || time.Now().After(deadline) {
			t.Fatalf("box helper didn't start:\n%s", h.Output())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (f *fwLab) expect(t *testing.T, from, to string, want map[string]string) {
	t.Helper()
	var ports []string
	for p := range want {
		ports = append(ports, p)
	}
	out, err := f.lab.Run(f.rtr, "dial", "DIAL_FROM="+from, "DIAL_TO="+to, "DIAL_PORTS="+strings.Join(ports, ","))
	if err != nil {
		t.Fatalf("dial: %v\n%s", err, out)
	}
	for p, w := range want {
		if !strings.Contains(out, p+"="+w) {
			t.Errorf("from %s to %s port %s: want %s, got:\n%s", from, to, p, w, out)
		}
	}
}

func TestFirewallAllowListInANamespace(t *testing.T) {
	f := newFwLab(t)
	f.startBox(t, firewall.Table{MgmtIf: "mgmt0", AllowV4: prefixes("192.0.2.50/32"), Open22: true, Open8443: true})
	f.expect(t, "192.0.2.50", "192.0.2.10", map[string]string{"22": "ok", "8443": "ok", "9000": "ok"})
	f.expect(t, "192.0.2.60", "192.0.2.10", map[string]string{"22": "closed", "8443": "closed", "9000": "ok"})
	// The allow-list holds no IPv6 prefix, so IPv6 has no way in.
	f.expect(t, "2001:db8::50", "2001:db8::10", map[string]string{"22": "closed", "8443": "closed", "9000": "ok"})
	// 22 and 8443 never answer on the service interface.
	f.expect(t, "198.51.100.50", "198.51.100.10", map[string]string{"22": "closed", "8443": "closed", "9000": "ok"})
}

func TestFirewallClosedUntilTheStepOpensIt(t *testing.T) {
	f := newFwLab(t)
	f.startBox(t, firewall.Table{MgmtIf: "mgmt0", Open22: true})
	f.expect(t, "192.0.2.60", "192.0.2.10", map[string]string{"22": "ok", "8443": "closed"})
	f.expect(t, "2001:db8::50", "2001:db8::10", map[string]string{"22": "ok", "8443": "closed"})
}

func TestFirewallRewriteIsWhole(t *testing.T) {
	f := newFwLab(t)
	f.startBox(t, firewall.Table{MgmtIf: "mgmt0", Open22: true, Open8443: true, AllowV6: prefixes("2001:db8::/64", "2001:db8::50/128")})
	f.expect(t, "2001:db8::50", "2001:db8::10", map[string]string{"22": "ok", "8443": "ok"})
	f.expect(t, "192.0.2.50", "192.0.2.10", map[string]string{"22": "closed", "8443": "closed"})
}
