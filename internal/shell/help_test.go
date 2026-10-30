// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

// Every command and command group, in both origins and with a product
// installed, carries its purpose (Short and Long) and an example.
func TestEveryCommandIsDocumented(t *testing.T) {
	values := []shell.Value{{Name: "setup-token", Label: "Sneakers setup token"}}
	for _, o := range []shell.Origin{shell.OriginSSH, shell.OriginConsole} {
		var walk func(c *cobra.Command)
		n := 0
		walk = func(c *cobra.Command) {
			n++
			if strings.TrimSpace(c.Short) == "" || strings.TrimSpace(c.Long) == "" || strings.TrimSpace(c.Example) == "" {
				t.Errorf("%s: %q lacks a short or long description or an example", o, c.CommandPath())
			}
			for _, sub := range c.Commands() {
				walk(sub)
			}
		}
		walk(shell.Tree(o, sneakers, values...))
		if n < 20 {
			t.Fatalf("%s: only %d commands walked", o, n)
		}
	}
}

// help network set lists every key the parser takes, each with an
// example; so do "network set" alone and "network set ?", without
// asking the appliance anything.
func TestNetworkSetListsEveryKey(t *testing.T) {
	keys := shell.NetworkKeys()
	if len(keys) < 7 {
		t.Fatalf("keys %v", keys)
	}
	for _, line := range []string{"help network set", "network set", "network set ?"} {
		r := runShellIn(t, shell.OriginSSH, line, "", nil)
		if r.e != nil {
			t.Fatalf("%q: %v %s", line, r.e, r.err)
		}
		for _, k := range keys {
			if !strings.Contains(r.out, k.Name+"=") || !strings.Contains(r.out, k.Example) || !strings.Contains(r.out, k.Help) {
				t.Errorf("%q doesn't list %s with its example:\n%s", line, k.Name, r.out)
			}
		}
		if len(r.b.calls) != 0 {
			t.Fatalf("%q asked the appliance: %v", line, r.b.calls)
		}
	}
	for _, want := range []string{"hostname", "dns", "search", "ntp", "allow-list", "time-zone", "https-proxy"} {
		found := false
		for _, k := range keys {
			found = found || k.Name == want
		}
		if !found {
			t.Errorf("no %s key", want)
		}
	}
}

// A key the parser doesn't know, or a word without "=", says what was
// probably meant, and nothing is sent.
func TestNetworkSetSuggestsTheClosestKey(t *testing.T) {
	for line, want := range map[string]string{
		"network set hostnmae=box1.sneakers.example.org": `did you mean hostname?`,
		"network set timezone=UTC":                       `did you mean time-zone?`,
		"network set https_proxy=http://192.0.2.8:3128":  `did you mean https-proxy?`,
		"network set dns":                                `did you mean dns=<value>?`,
	} {
		r := runShellIn(t, shell.OriginSSH, line, "", nil)
		assertCode(t, r.e, "SHELL_PARSE")
		if !strings.Contains(r.err, want) {
			t.Errorf("%q said %q, want %q", line, r.err, want)
		}
		if len(r.b.calls) != 0 {
			t.Fatalf("%q asked the appliance: %v", line, r.b.calls)
		}
	}
	r := runShellIn(t, shell.OriginSSH, "network set mtu=9000", "", nil)
	assertCode(t, r.e, "SHELL_PARSE")
	if strings.Contains(r.err, "did you mean") || !strings.Contains(r.err, "help network set") {
		t.Errorf("a key with nothing close: %q", r.err)
	}
}

// The ipv4= and ipv6= modes are checked in the shell: an address there is
// sent to the key it belongs in, any other bad value gets the valid modes,
// and nothing is sent either way.
func TestNetworkSetChecksTheMode(t *testing.T) {
	const (
		v4Hint = `"ipv4" takes dhcp, static or off; put the address in ipv4-address= (for example: network set ipv4=static ipv4-address=192.0.2.10/24 ipv4-gateway=192.0.2.1)`
		v6Hint = `"ipv6" takes slaac, dhcpv6, static or off; put the address in ipv6-address= (for example: network set ipv6=static ipv6-address=2001:db8::10/64 ipv6-gateway=2001:db8::1)`
	)
	for _, tc := range []struct{ line, want string }{
		{"network set ipv4=192.0.2.50/16 ipv4-gateway=192.0.2.1", v4Hint},
		{"network set ipv4=192.0.2.50", v4Hint},
		{"network set ipv4=192.0.2.50/33", v4Hint},
		{"network set ipv6=2001:db8::5/64", v6Hint},
		{"network set ipv6=2001:db8::5", v6Hint},
		{"network set ipv4=bogus", `"ipv4" takes dhcp, static or off, not "bogus"`},
		{"network set ipv4=", `"ipv4" takes dhcp, static or off, not ""`},
		{"network set ipv4=STATIC", `"ipv4" takes dhcp, static or off, not "STATIC"`},
		{"network set ipv6=dhcp", `"ipv6" takes slaac, dhcpv6, static or off, not "dhcp"`},
		// An address of the other family doesn't belong in this key's
		// address key either, so it gets the valid modes.
		{"network set ipv4=2001:db8::5/64", `"ipv4" takes dhcp, static or off, not "2001:db8::5/64"`},
		{"network set ipv6=192.0.2.50/24", `"ipv6" takes slaac, dhcpv6, static or off, not "192.0.2.50/24"`},
	} {
		r := runShellIn(t, shell.OriginSSH, tc.line, "", nil)
		assertCode(t, r.e, "SHELL_PARSE")
		if !strings.Contains(r.err, tc.want) {
			t.Errorf("%q said %q, want %q", tc.line, r.err, tc.want)
		}
		if len(r.b.calls) != 0 {
			t.Fatalf("%q asked the appliance: %v", tc.line, r.b.calls)
		}
	}
	for _, line := range []string{
		"network set ipv4=static",
		"network set ipv4=dhcp",
		"network set ipv4=off",
		"network set ipv6=slaac",
		"network set ipv6=dhcpv6",
		"network set ipv6=static",
		"network set ipv6=off",
	} {
		r := runShellIn(t, shell.OriginSSH, line, "", nil)
		if r.e != nil {
			t.Errorf("%q: %v %s", line, r.e, r.err)
		}
		if len(r.b.calls) == 0 {
			t.Errorf("%q wasn't sent to the appliance", line)
		}
	}
}

// help network set shows the mode and address together for both families.
func TestNetworkSetHelpShowsTheFullForm(t *testing.T) {
	r := runShellIn(t, shell.OriginSSH, "help network set", "", nil)
	if r.e != nil {
		t.Fatalf("%v %s", r.e, r.err)
	}
	for _, want := range []string{
		"network set ipv4=static ipv4-address=192.0.2.10/24 ipv4-gateway=192.0.2.1",
		"network set ipv6=static ipv6-address=2001:db8::10/64 ipv6-gateway=2001:db8::1",
	} {
		if !strings.Contains(r.out, want) {
			t.Errorf("help lacks %q:\n%s", want, r.out)
		}
	}
}

// docs/cli.md is generated from the command tree; regenerate it with
// go run ./build/tools/clidoc.
func TestTheCLIReferenceIsCurrent(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "cli.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != shell.Reference() {
		t.Fatal("docs/cli.md isn't the command tree's reference; run go run ./build/tools/clidoc")
	}
}
