// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

const good = `format: 2
exposed_values:
  - name: setup-token
    secret: sneakers/sneakers-setup-token
    key: SETUP_TOKEN
    roles: [owner, admin]
    one_time: true
    consumed_when:
      service: sneakers/sneakers-gateway:http
      path: /setup/state
      field: needsSetup
      equals: false
    label: "Sneakers setup token"
    link: "https://{host}/admin/setup"
  - name: support-id
    secret: sneakers/sneakers-support
    key: SUPPORT_ID
    roles: [owner]
`

func TestAProductYAMLParses(t *testing.T) {
	s, err := productspec.Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.ExposedValues) != 2 {
		t.Fatalf("%+v", s)
	}
	v := s.ExposedValues[0]
	if v.Name != "setup-token" || v.Namespace() != "sneakers" || v.SecretName() != "sneakers-setup-token" || v.Key != "SETUP_TOKEN" || !v.OneTime || v.ConsumedWhen == nil {
		t.Fatalf("%+v", v)
	}
	if !v.Allows("owner") || !v.Allows("admin") || s.ExposedValues[1].Allows("admin") {
		t.Fatal("roles")
	}
	if got := v.LinkFor("box1.sneakers.example.org"); got != "https://box1.sneakers.example.org/admin/setup" {
		t.Fatalf("link %q", got)
	}
	if e, ok := s.Find("support-id"); !ok || e.Key != "SUPPORT_ID" {
		t.Fatal("Find")
	}
	if _, ok := s.Find("SETUP_TOKEN"); ok {
		t.Fatal("Find matched a key, not a name")
	}
}

func TestAProductYAMLIsRefusedWhenItBreaksARule(t *testing.T) {
	cases := map[string]string{
		"format 1":         "format: 1\n",
		"an unknown field": "format: 2\nlist_secrets: true\n",
		"an unknown role": `format: 2
exposed_values:
  - {name: a, secret: ns/s, key: K, roles: [root]}`,
		"no roles": `format: 2
exposed_values:
  - {name: a, secret: ns/s, key: K}`,
		"a secret without a namespace": `format: 2
exposed_values:
  - {name: a, secret: s, key: K, roles: [owner]}`,
		"a secret with a wildcard": `format: 2
exposed_values:
  - {name: a, secret: "ns/*", key: K, roles: [owner]}`,
		"a bad key": `format: 2
exposed_values:
  - {name: a, secret: ns/s, key: "a/b", roles: [owner]}`,
		"a bad name": `format: 2
exposed_values:
  - {name: "Setup Token", secret: ns/s, key: K, roles: [owner]}`,
		"a reserved name": `format: 2
exposed_values:
  - {name: mcp, secret: ns/s, key: K, roles: [owner]}`,
		"a name twice": `format: 2
exposed_values:
  - {name: a, secret: ns/s, key: K, roles: [owner]}
  - {name: a, secret: ns/t, key: K, roles: [owner]}`,
		"one_time without consumed_when": `format: 2
exposed_values:
  - {name: a, secret: ns/s, key: K, roles: [owner], one_time: true}`,
		"a bad signal service": `format: 2
exposed_values:
  - {name: a, secret: ns/s, key: K, roles: [owner], one_time: true, consumed_when: {service: gw, path: /s, field: f, equals: false}}`,
		"a signal path that leaves its service": `format: 2
exposed_values:
  - {name: a, secret: ns/s, key: K, roles: [owner], one_time: true, consumed_when: {service: "ns/gw:http", path: "/../../secrets", field: f, equals: false}}`,
		"a link that isn't https": `format: 2
exposed_values:
  - {name: a, secret: ns/s, key: K, roles: [owner], link: "http://{host}/x"}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := productspec.Parse([]byte(doc)); !codes.Is(err, codes.KitBundleMismatch) {
				t.Fatalf("err %v", err)
			}
		})
	}
}

// A bundle without product.yaml exposes nothing.
func TestNoProductYAMLExposesNothing(t *testing.T) {
	s, err := productspec.Load(t.TempDir())
	if err != nil || len(s.ExposedValues) != 0 {
		t.Fatalf("%+v %v", s, err)
	}
}

// The RBAC the appliance renders for the declared values: one service
// account, and in each namespace a Role that may only get the declared
// Secrets by name (and the declared signal's service proxy), never list or
// watch anything.
func TestTheRBACNamesOnlyTheDeclaredSecrets(t *testing.T) {
	s, err := productspec.Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	out := productspec.RBAC(s)
	var roles int
	for _, doc := range strings.Split(string(out), "\n---\n") {
		var obj struct {
			Kind     string `yaml:"kind"`
			Metadata struct {
				Name, Namespace string
			} `yaml:"metadata"`
			Rules []struct {
				APIGroups     []string `yaml:"apiGroups"`
				Resources     []string `yaml:"resources"`
				ResourceNames []string `yaml:"resourceNames"`
				Verbs         []string `yaml:"verbs"`
			} `yaml:"rules"`
			Subjects []struct {
				Kind, Name, Namespace string
			} `yaml:"subjects"`
		}
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			t.Fatalf("%v\n%s", err, doc)
		}
		switch obj.Kind {
		case "Role":
			roles++
			if obj.Metadata.Namespace != "sneakers" {
				t.Fatalf("a Role in %q", obj.Metadata.Namespace)
			}
			for _, r := range obj.Rules {
				if !slices.Equal(r.Verbs, []string{"get"}) || len(r.ResourceNames) == 0 {
					t.Fatalf("rule %+v", r)
				}
				switch {
				case slices.Equal(r.Resources, []string{"secrets"}):
					if !slices.Equal(r.ResourceNames, []string{"sneakers-setup-token", "sneakers-support"}) {
						t.Fatalf("secrets %v", r.ResourceNames)
					}
				case slices.Equal(r.Resources, []string{"services/proxy"}):
					if !slices.Equal(r.ResourceNames, []string{"sneakers-gateway:http"}) {
						t.Fatalf("services %v", r.ResourceNames)
					}
				default:
					t.Fatalf("resources %v", r.Resources)
				}
			}
		case "ClusterRole", "ClusterRoleBinding":
			t.Fatalf("a %s", obj.Kind)
		case "RoleBinding":
			if len(obj.Subjects) != 1 || obj.Subjects[0].Name != productspec.ServiceAccount || obj.Subjects[0].Namespace != productspec.Namespace {
				t.Fatalf("subjects %+v", obj.Subjects)
			}
		}
	}
	if roles != 1 {
		t.Fatalf("%d Roles\n%s", roles, out)
	}
	if strings.Contains(string(out), "list") || strings.Contains(string(out), "watch") {
		t.Fatalf("list or watch\n%s", out)
	}
}

func TestWriteRBACAndLoadFromASlot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, productspec.File), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := productspec.WriteRBAC(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, productspec.RBACFile)); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()
	if err := productspec.WriteRBAC(empty); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(empty, productspec.RBACFile)); !os.IsNotExist(err) {
		t.Fatalf("a bundle with no values got RBAC: %v", err)
	}
}

// The Sneakers bundle's product.yaml (in the build kit, not in the
// appliance's code) parses and exposes its setup token to owners and
// admins, consumed once the gateway has its first admin.
func TestTheSneakersBundleExposesItsSetupToken(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "product", "sneakers", "product.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := productspec.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := s.Find("setup-token")
	if !ok || !v.Allows("owner") || !v.Allows("admin") || !v.OneTime || v.ConsumedWhen == nil || v.LinkFor("box1.sneakers.example.org") != "https://box1.sneakers.example.org/admin/setup" {
		t.Fatalf("%+v", v)
	}
}
