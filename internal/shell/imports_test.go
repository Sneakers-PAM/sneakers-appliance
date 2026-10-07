// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestNoProgramExec is the static half of the no-exec guarantee: neither
// the shell package nor its binary links anything that starts a program,
// so no command line can reach /bin/sh whatever the parser does.
func TestNoProgramExec(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go tool on PATH")
	}
	for _, pkg := range []string{".", "../../cmd/sneakers-shell"} {
		out, err := exec.Command(gobin, "list", "-deps", "-f", "{{.ImportPath}}", pkg).Output() // #nosec G204 -- the go tool on fixed arguments
		if err != nil {
			t.Fatalf("go list %s: %v", pkg, err)
		}
		for _, dep := range strings.Fields(string(out)) {
			if dep == "os/exec" || dep == "plugin" {
				t.Errorf("%s links %s", pkg, dep)
			}
		}
	}
}
