// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package rootshell_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// sh runs script after the start file in a POSIX shell: the box's busybox
// when SNEAKERS_TEST_BUSYBOX names it, else /bin/sh.
func sh(t *testing.T, script string) (string, error) {
	t.Helper()
	shell, args := "/bin/sh", []string{"-c"}
	if bb := os.Getenv("SNEAKERS_TEST_BUSYBOX"); bb != "" {
		shell, args = bb, []string{"sh", "-c"}
	}
	rc, err := filepath.Abs("rc.sh")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(shell, append(args, ". "+rc+"\n"+script)...).CombinedOutput() // #nosec G204 -- the test's own shell
	return string(out), err
}

// help lists the troubleshooting commands and says why helm list is empty.
func TestHelpListsTheTroubleshootingCommands(t *testing.T) {
	out, err := sh(t, "help")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"kubectl get pods -A", "kubectl logs", "k0s status", "helm list -A is empty", "k0s\nmanifests", "exit leaves"} {
		if !strings.Contains(out, want) {
			t.Errorf("help lacks %q:\n%s", want, out)
		}
	}
}

// Before a product is installed kubectl, helm and k0s say so, instead of a
// bare "not found".
func TestKubectlAndHelmSayTheyComeWithTheProduct(t *testing.T) {
	for _, cmd := range []string{"kubectl get pods -A", "helm list -A", "k0s status"} {
		out, err := sh(t, "sneakers_product=/nonexistent\n"+cmd)
		if err == nil || !strings.Contains(out, "No product is installed yet") || strings.Contains(out, "not found") {
			t.Errorf("%s: %v\n%s", cmd, err, out)
		}
	}
}
