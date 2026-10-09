// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productedge_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/productedge"
)

type secret struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name, Namespace string
	} `yaml:"metadata"`
	StringData map[string]string `yaml:"stringData"`
}

// readSecret reads the box-tls Secret from a stack file.
func readSecret(t *testing.T, p string) secret {
	t.Helper()
	b, err := os.ReadFile(p) // #nosec G304 -- a test file
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range strings.Split(string(b), "\n---\n") {
		var s secret
		if err := yaml.Unmarshal([]byte(doc), &s); err != nil {
			t.Fatalf("%v\n%s", err, doc)
		}
		if s.Kind == "Secret" {
			return s
		}
	}
	t.Fatal("no Secret")
	return secret{}
}

// The edge serves the box's own certificate until one is set; a set one is
// kept on the state volume and goes into the box-tls Secret, with the
// dynamic config Traefik reloads when its volume changes.
func TestTheEdgeTakesASetCertificateLive(t *testing.T) {
	dir := t.TempDir()
	e := &productedge.Edge{Slot: filepath.Join(dir, "slot"), Dir: filepath.Join(dir, "platform", "tls"), AdminDir: filepath.Join(dir, "osadmin"), Manifests: filepath.Join(dir, "k0s", "manifests")}
	if e.Installed() {
		t.Fatal("installed with no slot")
	}
	if err := os.MkdirAll(e.Slot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.Slot, "bundle.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !e.Installed() {
		t.Fatal("not installed")
	}
	if err := os.MkdirAll(e.AdminDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for n, v := range map[string]string{"tls.crt": "OWN-CRT\n", "tls.key": "OWN-KEY\n"} {
		if err := os.WriteFile(filepath.Join(e.AdminDir, n), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	crt, key, err := e.Current()
	if err != nil || string(crt) != "OWN-CRT\n" || string(key) != "OWN-KEY\n" {
		t.Fatalf("%q %q %v", crt, key, err)
	}
	if err := e.Set([]byte("-----BEGIN CERTIFICATE-----\nNEW\n-----END CERTIFICATE-----\n"), []byte("-----BEGIN PRIVATE KEY-----\nNEWKEY\n-----END PRIVATE KEY-----\n")); err != nil {
		t.Fatal(err)
	}
	crt, _, _ = e.Current()
	if !strings.Contains(string(crt), "NEW") {
		t.Fatalf("current %q", crt)
	}
	stack := filepath.Join(e.Manifests, productedge.Stack, productedge.Stack+".yaml")
	if fi, err := os.Stat(stack); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	s := readSecret(t, stack)
	if s.Metadata.Name != "box-tls" || s.Metadata.Namespace != "sneakers-edge" || !strings.Contains(s.StringData["tls.crt"], "NEW") || !strings.Contains(s.StringData["tls.key"], "NEWKEY") {
		t.Fatalf("%+v", s)
	}
	var dyn struct {
		TLS struct {
			Stores map[string]struct {
				DefaultCertificate struct {
					CertFile string `yaml:"certFile"`
					KeyFile  string `yaml:"keyFile"`
				} `yaml:"defaultCertificate"`
			} `yaml:"stores"`
		} `yaml:"tls"`
	}
	if err := yaml.Unmarshal([]byte(s.StringData[productedge.DynamicKey]), &dyn); err != nil {
		t.Fatal(err)
	}
	if d := dyn.TLS.Stores["default"].DefaultCertificate; !strings.Contains(d.CertFile, "NEW") || !strings.Contains(d.KeyFile, "NEWKEY") {
		t.Fatalf("dynamic %+v", d)
	}
}

// Reset drops the assigned certificate: the edge serves the box's own again.
func TestResetGoesBackToTheBoxsOwnCertificate(t *testing.T) {
	dir := t.TempDir()
	e := &productedge.Edge{Slot: filepath.Join(dir, "slot"), Dir: filepath.Join(dir, "platform", "tls"), AdminDir: filepath.Join(dir, "osadmin"), Manifests: filepath.Join(dir, "k0s", "manifests")}
	if err := os.MkdirAll(e.AdminDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for n, v := range map[string]string{"tls.crt": "OWN-CRT\n", "tls.key": "OWN-KEY\n"} {
		if err := os.WriteFile(filepath.Join(e.AdminDir, n), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Set([]byte("NEW\n"), []byte("NEWKEY\n")); err != nil {
		t.Fatal(err)
	}
	if err := e.Reset(); err != nil {
		t.Fatal(err)
	}
	crt, _, err := e.Current()
	if err != nil || string(crt) != "OWN-CRT\n" {
		t.Fatalf("%q %v", crt, err)
	}
	if s := readSecret(t, filepath.Join(e.Manifests, productedge.Stack, productedge.Stack+".yaml")); s.StringData["tls.crt"] != "OWN-CRT\n" {
		t.Fatalf("%+v", s.StringData)
	}
}
