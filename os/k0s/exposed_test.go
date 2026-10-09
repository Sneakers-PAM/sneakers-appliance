// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package k0s_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

func exposedRBAC(t *testing.T, slot, stack string) {
	t.Helper()
	b, err := os.ReadFile("k0s-interim")
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?ms)^exposed_rbac\(\) \{\n.*?^\}\n`).Find(b)
	if fn == nil {
		t.Fatal("k0s-interim has no exposed_rbac function")
	}
	script := "set -eu\nsay() { :; }\n" + string(fn) + `exposed_rbac "$1" "$2"` + "\n"
	if out, err := exec.Command("sh", "-c", script, "sh", slot, stack).CombinedOutput(); err != nil { // #nosec G204 -- the repo's own script
		t.Fatalf("exposed_rbac: %v: %s", err, out)
	}
}

// The RBAC the appliance rendered for a bundle's exposed values goes in as
// its own stack; a bundle that exposes none leaves no stack, and k0s
// removes what an earlier bundle's held.
func TestTheExposedValuesRBACFollowsTheInstalledBundle(t *testing.T) {
	dir := t.TempDir()
	slot, stack := filepath.Join(dir, "slot"), filepath.Join(dir, "manifests", "sneakers-appliance-exposed")
	if err := os.MkdirAll(slot, 0o755); err != nil {
		t.Fatal(err)
	}
	rbac := []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: sneakers-appliance\n")
	if err := os.WriteFile(filepath.Join(slot, "exposed-rbac.yaml"), rbac, 0o600); err != nil {
		t.Fatal(err)
	}
	exposedRBAC(t, slot, stack)
	got, err := os.ReadFile(filepath.Join(stack, "exposed-rbac.yaml")) // #nosec G304 -- the test's own file
	if err != nil || string(got) != string(rbac) {
		t.Fatalf("%q %v", got, err)
	}
	if err := os.Remove(filepath.Join(slot, "exposed-rbac.yaml")); err != nil {
		t.Fatal(err)
	}
	exposedRBAC(t, slot, stack)
	if _, err := os.Stat(stack); !os.IsNotExist(err) {
		t.Fatal("the stack outlived the bundle's RBAC")
	}
	exposedRBAC(t, slot, stack)
}
