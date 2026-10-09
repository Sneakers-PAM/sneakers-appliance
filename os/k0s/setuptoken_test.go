// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package k0s_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func setupTokenSecret(t *testing.T, token, stack string) {
	t.Helper()
	b, err := os.ReadFile("k0s-interim")
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?ms)^setup_token_secret\(\) \{\n.*?^\}\n`).Find(b)
	if fn == nil {
		t.Fatal("k0s-interim has no setup_token_secret function")
	}
	script := "set -eu\nsay() { :; }\n" + string(fn) + `setup_token_secret "$1" "$2"` + "\n"
	if out, err := exec.Command("sh", "-c", script, "sh", token, stack).CombinedOutput(); err != nil { // #nosec G204 -- the repo's own script
		t.Fatalf("setup_token_secret: %v: %s", err, out)
	}
}

// While osadmin's product setup token is unused, k0s gets it as the
// sneakers-setup-token Secret for the gateway; once it's consumed, the
// stack goes and k0s deletes the Secret.
func TestTheSetupTokenIsTheProductsSecretUntilUsed(t *testing.T) {
	dir := t.TempDir()
	token, stack := filepath.Join(dir, "token"), filepath.Join(dir, "manifests", "product-setup")
	if err := os.WriteFile(token, []byte("stp_abcdefghijklmnopqrstuvwxyz234567\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setupTokenSecret(t, token, stack)
	b, err := os.ReadFile(filepath.Join(stack, "setup-token.yaml")) // #nosec G304 -- the test's own file
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"kind: Secret", "name: sneakers-setup-token", "namespace: sneakers", `SETUP_TOKEN: "stp_abcdefghijklmnopqrstuvwxyz234567"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the Secret lacks %q:\n%s", want, b)
		}
	}
	if fi, err := os.Stat(filepath.Join(stack, "setup-token.yaml")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v %v", fi, err)
	}
	if err := os.Remove(token); err != nil {
		t.Fatal(err)
	}
	setupTokenSecret(t, token, stack)
	if _, err := os.Stat(stack); !os.IsNotExist(err) {
		t.Fatal("the stack outlived the token")
	}
	setupTokenSecret(t, token, stack)
}
