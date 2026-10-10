// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package network_test

import (
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The root image has no zoneinfo database (build/root/tree.txt), so a
// binary that checks or shows a time zone must carry its own: without
// time/tzdata, time.LoadLocation("America/New_York") fails on the box
// and network set time-zone= is refused, although it passes on any
// build host that has /usr/share/zoneinfo. Every binary that links this
// package, or the console's screens, must link time/tzdata.
func TestEveryBinaryThatReadsATimeZoneCarriesTzdata(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool:", err)
	}
	list := exec.Command(gobin, "list", "-f", `{{.ImportPath}} {{join .Deps " "}}`, "./cmd/...") // #nosec G204 -- the go tool on the repository's own packages
	list.Dir = filepath.Join("..", "..")
	out, err := list.Output()
	if err != nil {
		t.Fatal(err)
	}
	const mod = "github.com/Sneakers-PAM/sneakers-appliance/"
	checked := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		deps := f[1:]
		if !slices.Contains(deps, mod+"internal/network") && !slices.Contains(deps, mod+"internal/consoleui") {
			continue
		}
		checked++
		if !slices.Contains(deps, "time/tzdata") {
			t.Errorf("%s reads time zones but doesn't link time/tzdata; add import _ \"time/tzdata\" to its main", f[0])
		}
	}
	if checked < 5 {
		t.Fatalf("only %d binaries checked", checked)
	}
}
