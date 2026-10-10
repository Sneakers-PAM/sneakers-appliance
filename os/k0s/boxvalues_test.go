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

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxvalues"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

func placeStack(t *testing.T, src, dst, placeholders, values, kernelHost string) {
	t.Helper()
	b, err := os.ReadFile("k0s-interim")
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?ms)^place_stack\(\) \{\n.*?^\}\n`).Find(b)
	if fn == nil {
		t.Fatal("k0s-interim has no place_stack function")
	}
	script := "set -eu\n" + string(fn) + `place_stack "$1" "$2" "$3" "$4" "$5"` + "\n"
	if out, err := exec.Command("sh", "-c", script, "sh", src, dst, placeholders, values, kernelHost).CombinedOutput(); err != nil { // #nosec G204 -- the repo's own script
		t.Fatalf("place_stack: %v: %s", err, out)
	}
}

// The Sneakers bundle's placeholder.
const placeholder = "sneakers.box.invalid" // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved

var hostStack = strings.ReplaceAll(`apiVersion: v1
kind: ConfigMap
metadata:
  name: kratos-config
data:
  kratos.yaml: |
    serve:
      public:
        base_url: https://PH/
    selfservice:
      allowed_return_urls:
        - https://PH/
    webauthn:
      rp:
        id: PH
        origins: [https://PH]
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: sneakers-mcp-switch
data:
  HYDRA_ISSUER: https://PH/oauth
  MCP_URL: https://PH/mcp
`, "PH", placeholder)

// k0s-interim puts a stack in front of k0s with the box's own values in
// place of the bundle's placeholders, the same as productswitch does
// (boxvalues.Substitute): the recorded FQDN, else the kernel's host name;
// a slot that declares no box values is copied as it is.
func TestK0sInterimPutsTheBoxsValuesInTheStacks(t *testing.T) {
	for _, c := range []struct {
		name, placeholders, values, kernel string
	}{
		{"recorded", placeholder + " box.fqdn\n", "box.fqdn box1.example.org\n", "sneakers-0a1b2c3d"},
		{"another box", placeholder + " box.fqdn\n", "box.fqdn [2001:db8::10]\n", "sneakers-0a1b2c3d"},
		{"none recorded", placeholder + " box.fqdn\n", "", "sneakers-0a1b2c3d"},
		{"no box values", "", "box.fqdn box1.example.org\n", "sneakers-0a1b2c3d"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			src, dst := filepath.Join(dir, "slot", "manifests", "sneakers")+"/", filepath.Join(dir, "k0s", "manifests", "sneakers")
			if err := os.MkdirAll(src, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(src, "sneakers.yaml"), []byte(hostStack), 0o644); err != nil {
				t.Fatal(err)
			}
			slot, platform := filepath.Join(dir, "slot"), filepath.Join(dir, "platform")
			if err := os.MkdirAll(platform, 0o700); err != nil {
				t.Fatal(err)
			}
			if c.placeholders != "" {
				if err := os.WriteFile(filepath.Join(slot, productspec.BoxValuesFile), []byte(c.placeholders), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if c.values != "" {
				if err := os.WriteFile(filepath.Join(platform, boxvalues.File), []byte(c.values), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			placeStack(t, src, dst, filepath.Join(slot, productspec.BoxValuesFile), filepath.Join(platform, boxvalues.File), c.kernel)
			got := string(mustRead(t, filepath.Join(dst, "sneakers.yaml")))
			want := string(boxvalues.Substitute([]byte(hostStack), boxvalues.Table(slot, boxvalues.Read(platform), c.kernel)))
			if got != want {
				t.Fatalf("k0s-interim:\n%s\nboxvalues:\n%s", got, want)
			}
			if c.placeholders != "" && strings.Contains(got, ".invalid") {
				t.Fatalf("a placeholder is left:\n%s", got)
			}
		})
	}
}

// The Base OS and Base Web versions the box recorded go into a stack the
// same way as its FQDN.
func TestK0sInterimPutsTheBoxsVersionsInTheStacks(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "slot")+"/", filepath.Join(dir, "k0s")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	stack := "env:\n  SNEAKERS_APPLIANCE_VERSION: baseos-version.invalid\n  SNEAKERS_APPLIANCE_WEB_VERSION: baseweb-version.invalid\n  SNEAKERS_APPLIANCE_FQDN: " + placeholder + "\n" // scrub:allow=fqdn -- the reserved .invalid placeholders, never resolved
	if err := os.WriteFile(filepath.Join(src, "sneakers.yaml"), []byte(stack), 0o644); err != nil {
		t.Fatal(err)
	}
	placeholders := filepath.Join(dir, "box-values.slot")
	if err := os.WriteFile(placeholders, []byte(placeholder+" box.fqdn\nbaseos-version.invalid box.os.version\nbaseweb-version.invalid box.web.version\n"), 0o644); err != nil { // scrub:allow=fqdn -- the reserved .invalid placeholders, never resolved
		t.Fatal(err)
	}
	state := t.TempDir()
	if err := boxvalues.Write(state, map[string]string{productspec.BoxFQDN: "box1.example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := boxvalues.RecordVersions(state, "0.1.0-m+lab.2", "0.1.0-m"); err != nil {
		t.Fatal(err)
	}
	placeStack(t, src, dst, placeholders, filepath.Join(state, boxvalues.File), "sneakers-0a1b2c3d")
	got, err := os.ReadFile(filepath.Join(dst, "sneakers.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	want := "env:\n  SNEAKERS_APPLIANCE_VERSION: 0.1.0-m+lab.2\n  SNEAKERS_APPLIANCE_WEB_VERSION: 0.1.0-m\n  SNEAKERS_APPLIANCE_FQDN: box1.example.org\n"
	if string(got) != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}
