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

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productedge"
)

// k0s-interim's box-tls Secret is the one internal/productedge writes
// live: the chain, the key and Traefik's dynamic config with them inline.
func TestK0sInterimsBoxTLSIsProductedges(t *testing.T) {
	b, err := os.ReadFile("k0s-interim")
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?ms)^box_tls\(\) \{\n.*?^\}\n`).Find(b)
	if fn == nil {
		t.Fatal("k0s-interim has no box_tls function")
	}
	dir := t.TempDir()
	crt := "-----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----\n"
	key := "-----BEGIN PRIVATE KEY-----\nCCCC\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(filepath.Join(dir, "c"), []byte(crt), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "k"), []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "set -eu\n" + string(fn) + `box_tls "$1" "$2" "$3"` + "\n"
	stack := filepath.Join(dir, "stack")
	if out, err := exec.Command("sh", "-c", script, "sh", filepath.Join(dir, "c"), filepath.Join(dir, "k"), stack).CombinedOutput(); err != nil { // #nosec G204 -- the repo's own script
		t.Fatalf("box_tls: %v: %s", err, out)
	}
	shell := secretOf(t, mustRead(t, filepath.Join(stack, "box-tls.yaml")))
	goRendered, err := productedge.Render([]byte(crt), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	want := secretOf(t, goRendered)
	for _, k := range []string{"tls.crt", "tls.key"} {
		if shell[k] != want[k] {
			t.Errorf("%s: %q, want %q", k, shell[k], want[k])
		}
	}
	var a, w any
	if err := yaml.Unmarshal([]byte(shell[productedge.DynamicKey]), &a); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(want[productedge.DynamicKey]), &w); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(shell[productedge.DynamicKey], "BBBB") || yamlString(t, a) != yamlString(t, w) {
		t.Errorf("dynamic config:\n%s\nwant:\n%s", shell[productedge.DynamicKey], want[productedge.DynamicKey])
	}
}

func secretOf(t *testing.T, b []byte) map[string]string {
	t.Helper()
	for _, doc := range strings.Split(string(b), "\n---\n") {
		var s struct {
			Kind       string            `yaml:"kind"`
			StringData map[string]string `yaml:"stringData"`
		}
		if err := yaml.Unmarshal([]byte(doc), &s); err != nil {
			t.Fatalf("%v\n%s", err, doc)
		}
		if s.Kind == "Secret" {
			return s.StringData
		}
	}
	t.Fatal("no Secret")
	return nil
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) // #nosec G304 -- a test file
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func yamlString(t *testing.T, v any) string {
	t.Helper()
	b, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
