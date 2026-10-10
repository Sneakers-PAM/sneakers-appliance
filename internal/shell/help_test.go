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
