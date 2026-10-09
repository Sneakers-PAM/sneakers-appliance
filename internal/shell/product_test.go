// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productinfo"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

var sneakers = productinfo.Info{Name: "sneakers", Title: "Sneakers", Version: "0.2.0"}

func runProduct(t *testing.T, p productinfo.Info, line string) (string, string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	e := &shell.Env{Origin: shell.OriginSSH, Backend: &shell.Services{}, In: strings.NewReader(""), Out: &out, Err: &errb, Product: p}
	err := shell.Run(context.Background(), e, line)
	return out.String(), errb.String(), err
}

// With no product installed, the base shell offers nothing of a product's:
// no mcp command, and nothing in help mentions it.
func TestTheBaseShellHasNoProductCommands(t *testing.T) {
	for _, line := range []string{"mcp", "mcp off", "sneakers mcp"} {
		_, _, err := runProduct(t, productinfo.Info{}, line)
		assertCode(t, err, "SHELL_UNKNOWN")
	}
	out, _, err := runProduct(t, productinfo.Info{}, "help")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out), "mcp") || strings.Contains(strings.ToLower(out), "sneakers commands") {
		t.Fatalf("base help mentions the product:\n%s", out)
	}
	for _, o := range []shell.Origin{shell.OriginSSH, shell.OriginConsole} {
		for _, n := range shell.NamesFor(o, productinfo.Info{}) {
			if strings.Contains(n, "mcp") {
				t.Errorf("%s offers %q with no product", o, n)
			}
		}
	}
	if got := shell.CompleteFor(shell.OriginSSH, productinfo.Info{}, "mc"); got != "mc" {
		t.Fatalf("completes %q with no product", got)
	}
}

// An installed product's commands sit in a group named after it.
func TestAnInstalledProductAddsItsOwnGroup(t *testing.T) {
	_, stderr, err := runProduct(t, sneakers, "sneakers mcp off")
	if !codes.Is(err, codes.NotAvailable) || !strings.Contains(stderr, "Not available in this release") {
		t.Fatalf("sneakers mcp off: %v %q", err, stderr)
	}
	_, _, err = runProduct(t, sneakers, "mcp off")
	assertCode(t, err, "SHELL_UNKNOWN")
	out, _, err := runProduct(t, sneakers, "help")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "sneakers") || !strings.Contains(out, "Sneakers") {
		t.Fatalf("help doesn't list the product group:\n%s", out)
	}
	out, _, err = runProduct(t, sneakers, "help sneakers")
	if err != nil || !strings.Contains(out, "mcp") {
		t.Fatalf("help sneakers: %v\n%s", err, out)
	}
	names := shell.NamesFor(shell.OriginSSH, sneakers)
	if !slices.Contains(names, "sneakers mcp") || slices.Contains(names, "mcp") {
		t.Fatalf("names %v", names)
	}
	for typed, want := range map[string]string{"sne": "sneakers ", "sneakers ": "sneakers mcp ", "mc": "mc"} {
		if got := shell.CompleteFor(shell.OriginSSH, sneakers, typed); got != want {
			t.Errorf("CompleteFor(%q) = %q, want %q", typed, got, want)
		}
	}
}

// The base names stay the base: Names and Complete never include a
// product's commands.
func TestTheBaseNamesLeaveTheProductOut(t *testing.T) {
	if slices.ContainsFunc(shell.Names(shell.OriginSSH), func(n string) bool { return strings.Contains(n, "mcp") }) {
		t.Fatal("the base names list mcp")
	}
	if !slices.Equal(shell.Names(shell.OriginSSH), shell.NamesFor(shell.OriginSSH, productinfo.Info{})) {
		t.Fatal("Names differs from NamesFor with no product")
	}
}
