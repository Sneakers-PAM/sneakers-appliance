// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package productspec_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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
	// Every agreed component, MCP and Hydra among them, and the MCP switch,
	// off by default.
	var images []string
	for _, c := range s.Components {
		images = append(images, c.Image)
	}
	for _, want := range []string{"postgres", "valkey", "kratos", "hydra", "traefik", "cert-manager-controller", "sneakers-identity", "sneakers-vault", "sneakers-workflow",
		"sneakers-audit", "sneakers-notify", "sneakers-connector", "sneakers-sshbroker", "sneakers-gateway", "sneakers-mcp", "sneakers-web-staff", "sneakers-web-admin"} {
		if !slices.Contains(images, want) {
			t.Errorf("no component %s", want)
		}
	}
	if w, ok := s.Switch("mcp"); !ok || w.Default || !slices.Equal(w.Stacks, []string{"sneakers-mcp"}) {
		t.Errorf("the mcp switch %+v", w)
	}
	// The box's own name reaches every host-dependent setting through the
	// placeholder the bundle's values give global.host.
	// The box's Base OS and Base Web versions reach the product's About the
	// same way.
	want := []productspec.BoxValue{
		{Value: productspec.BoxFQDN, Placeholder: "sneakers.box.invalid"},          // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
		{Value: productspec.BoxOSVersion, Placeholder: "baseos-version.invalid"},   // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
		{Value: productspec.BoxWebVersion, Placeholder: "baseweb-version.invalid"}, // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
	}
	if !slices.Equal(s.BoxValues, want) {
		t.Errorf("box values %+v", s.BoxValues)
	}
}

const withSwitches = `format: 2
components:
  - {name: PostgreSQL, image: postgres}
  - {name: the MCP server, image: sneakers-mcp}
switches:
  - name: mcp
    label: The MCP server
    default: false
    stacks: [sneakers-mcp]
    restart: [sneakers/deployment/sneakers-gateway, sneakers/deployment/sneakers-web-staff]
`

func TestComponentsAndSwitchesParse(t *testing.T) {
	s, err := productspec.Parse([]byte(withSwitches))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Components) != 2 || s.Components[1].Image != "sneakers-mcp" {
		t.Fatalf("components %+v", s.Components)
	}
	sw, ok := s.Switch("mcp")
	if !ok || sw.Default || !slices.Equal(sw.Stacks, []string{"sneakers-mcp"}) || len(sw.Restart) != 2 {
		t.Fatalf("%+v", sw)
	}
	ns, kind, name, ok := sw.RestartRef(0)
	if !ok || ns != "sneakers" || kind != "deployment" || name != "sneakers-gateway" {
		t.Fatalf("restart %q %q %q", ns, kind, name)
	}
	for name, doc := range map[string]string{
		"a bad switch name":    "format: 2\nswitches:\n  - {name: MCP, stacks: [a]}\n",
		"a switch twice":       "format: 2\nswitches:\n  - {name: mcp, stacks: [a]}\n  - {name: mcp, stacks: [b]}\n",
		"no stacks":            "format: 2\nswitches:\n  - {name: mcp}\n",
		"a stack in two":       "format: 2\nswitches:\n  - {name: mcp, stacks: [a]}\n  - {name: api, stacks: [a]}\n",
		"a bad restart":        "format: 2\nswitches:\n  - {name: mcp, stacks: [a], restart: [sneakers/pod/x]}\n",
		"a component no image": "format: 2\ncomponents:\n  - {name: x}\n",
	} {
		if _, err := productspec.Parse([]byte(doc)); !codes.Is(err, codes.KitBundleMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A slot records which of its stacks each switch gates, with the
// default, for k0s-interim.
func TestTheSwitchStacksAreWrittenIntoTheSlot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, productspec.File), []byte(withSwitches), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := productspec.WriteRBAC(dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, productspec.SwitchStacksFile))
	if err != nil || string(b) != "mcp sneakers-mcp off\n" {
		t.Fatalf("%q %v", b, err)
	}
}

const withImport = good + `switches:
  - name: import
    label: Import from an earlier install
    default: false
    stacks: [sneakers-import]
import:
  label: Import from an earlier Sneakers
  switch: import
  job: import/job.yaml
  uid: 65532
  setup: setup-token
  restart: [sneakers/deployment/sneakers-vault]
`

// A product can take an export of an earlier install before its own
// first-run setup (docs/import.md).
func TestTheImportSectionParses(t *testing.T) {
	s, err := productspec.Parse([]byte(withImport))
	if err != nil {
		t.Fatal(err)
	}
	im := s.Import
	if im == nil || im.Switch != "import" || im.Job != "import/job.yaml" || im.UID != 65532 || im.Setup != "setup-token" || len(im.Restart) != 1 {
		t.Fatalf("%+v", im)
	}
	if st, ok := s.ImportStack(); !ok || st != "sneakers-import" {
		t.Fatalf("stack %q %v", st, ok)
	}
	base := good + "switches:\n  - {name: import, stacks: [sneakers-import]}\n"
	for name, doc := range map[string]string{
		"no such switch":     base + "import: {switch: other, job: import/job.yaml, uid: 65532, setup: setup-token}\n",
		"a job outside":      base + "import: {switch: import, job: ../job.yaml, uid: 65532, setup: setup-token}\n",
		"a job not yaml":     base + "import: {switch: import, job: import/job.sh, uid: 65532, setup: setup-token}\n",
		"root":               base + "import: {switch: import, job: import/job.yaml, uid: 0, setup: setup-token}\n",
		"setup not one-time": base + "import: {switch: import, job: import/job.yaml, uid: 65532, setup: support-id}\n",
		"a bad restart":      base + "import: {switch: import, job: import/job.yaml, uid: 65532, setup: setup-token, restart: [x]}\n",
	} {
		if _, err := productspec.Parse([]byte(doc)); !codes.Is(err, codes.KitBundleMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTheSneakersBundleTakesAnImport(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "product", "sneakers", "product.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := productspec.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if s.Import == nil || s.Import.Setup != "setup-token" {
		t.Fatalf("import %+v", s.Import)
	}
	if w, ok := s.Switch(s.Import.Switch); !ok || w.Default {
		t.Fatalf("the import switch %+v is off by default", w)
	}
	job, err := os.ReadFile(filepath.Join("..", "..", "build", "product", "sneakers", "import-job.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"${JOB_NAME}", "${ARGS}", "${HOST_DIR}", "MIGRATE_OUTPUT_FILE", "MIGRATE_OWNER_PASSWORD_FILE", "serviceAccountName: sneakers-migrate"} {
		if !strings.Contains(string(job), want) {
			t.Errorf("the job template lacks %s", want)
		}
	}
}

// A product names the keys its data can't be opened without; the box
// keeps them in the recovery escrow (docs/key-custody.md).
func TestTheEscrowKeysParseAndReachTheRBAC(t *testing.T) {
	doc := good + `escrow:
  - {name: vault-root-key, secret: sneakers/sneakers-vault-generated, key: VAULT_ROOT_KEK}
  - {name: totp-key, secret: sneakers/sneakers-identity-generated, key: TOTP_ENC_KEY}
`
	s, err := productspec.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Escrow) != 2 || s.Escrow[0].Namespace() != "sneakers" || s.Escrow[0].SecretName() != "sneakers-vault-generated" || s.Escrow[1].Key != "TOTP_ENC_KEY" {
		t.Fatalf("%+v", s.Escrow)
	}
	rbac := string(productspec.RBAC(s))
	for _, want := range []string{"sneakers-vault-generated", "sneakers-identity-generated", "sneakers-setup-token"} {
		if !strings.Contains(rbac, want) {
			t.Errorf("the RBAC doesn't name %s:\n%s", want, rbac)
		}
	}
	for name, bad := range map[string]string{
		"a bad name":   good + "escrow:\n  - {name: Root, secret: sneakers/s, key: K}\n",
		"twice":        good + "escrow:\n  - {name: a, secret: sneakers/s, key: K}\n  - {name: a, secret: sneakers/t, key: K}\n",
		"a bad secret": good + "escrow:\n  - {name: a, secret: s, key: K}\n",
		"a bad key":    good + "escrow:\n  - {name: a, secret: sneakers/s, key: \"K K\"}\n",
	} {
		if _, err := productspec.Parse([]byte(bad)); !codes.Is(err, codes.KitBundleMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTheSneakersBundleEscrowsItsVaultAndTOTPKeys(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "product", "sneakers", "product.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := productspec.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, e := range s.Escrow {
		names[e.Name] = true
	}
	if !names["vault-root-key"] || !names["totp-key"] {
		t.Fatalf("escrow %+v", s.Escrow)
	}
}

const withBoxValues = `format: 2
box_values:
  - {value: box.fqdn, placeholder: sneakers.box.invalid}  # scrub:allow=fqdn -- the reserved .invalid placeholder
`

// A product names the box values it reads by the placeholder its stacks
// carry; the slot records them for k0s-interim.
func TestBoxValuesParseAndAreWrittenIntoTheSlot(t *testing.T) {
	s, err := productspec.Parse([]byte(withBoxValues))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.BoxValues) != 1 || s.BoxValues[0].Value != productspec.BoxFQDN || s.BoxValues[0].Placeholder != "sneakers.box.invalid" { // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
		t.Fatalf("%+v", s.BoxValues)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, productspec.File), []byte(withBoxValues), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := productspec.WriteRBAC(dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, productspec.BoxValuesFile))
	if err != nil || string(b) != "sneakers.box.invalid box.fqdn\n" { // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
		t.Fatalf("%q %v", b, err)
	}
	// A bundle that names none leaves no file behind.
	if err := os.WriteFile(filepath.Join(dir, productspec.File), []byte("format: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := productspec.WriteRBAC(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, productspec.BoxValuesFile)); !os.IsNotExist(err) {
		t.Fatalf("the box-values file stayed: %v", err)
	}
}

// The box offers its FQDN and its Base OS and Base Web versions.
func TestEveryBoxValueTheBoxOffersParses(t *testing.T) {
	doc := "format: 2\nbox_values:\n  - {value: box.fqdn, placeholder: sneakers.box.invalid}\n" + // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
		"  - {value: box.os.version, placeholder: baseos-version.invalid}\n" + // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
		"  - {value: box.web.version, placeholder: baseweb-version.invalid}\n" // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
	s, err := productspec.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.BoxValues) != 3 || s.BoxValues[1].Value != productspec.BoxOSVersion || s.BoxValues[2].Value != productspec.BoxWebVersion {
		t.Fatalf("%+v", s.BoxValues)
	}
}

func TestABoxValueIsRefusedWhenItBreaksARule(t *testing.T) {
	for name, doc := range map[string]string{
		"an unknown value":         "format: 2\nbox_values:\n  - {value: box.serial, placeholder: serial.box.invalid}\n", // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
		"a resolvable name":        "format: 2\nbox_values:\n  - {value: box.fqdn, placeholder: sneakers.example.org}\n",
		"the bare .invalid":        "format: 2\nbox_values:\n  - {value: box.fqdn, placeholder: invalid}\n",                                                  // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
		"an upper-case name":       "format: 2\nbox_values:\n  - {value: box.fqdn, placeholder: Sneakers.box.invalid}\n",                                     // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
		"a value twice":            "format: 2\nbox_values:\n  - {value: box.fqdn, placeholder: a.invalid}\n  - {value: box.fqdn, placeholder: b.invalid}\n", // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
		"a placeholder with a /":   "format: 2\nbox_values:\n  - {value: box.fqdn, placeholder: a/b.invalid}\n",                                              // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
		"no placeholder":           "format: 2\nbox_values:\n  - {value: box.fqdn}\n",
		"a placeholder in another": "format: 2\nbox_values:\n  - {value: box.fqdn, placeholder: box.invalid}\n  - {value: box.os.version, placeholder: os.box.invalid}\n", // scrub:allow=fqdn -- the reserved .invalid placeholder, never resolved
	} {
		if _, err := productspec.Parse([]byte(doc)); !codes.Is(err, codes.KitBundleMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

const withBoxSecrets = `format: 2
box_secrets:
  - secret: sneakers/sneakers-bundled
    keys:
      - {key: password, generate: password}
      - {key: valkey-password, generate: password}
      - {key: redis-url, value: "redis://:{valkey-password}@sneakers-valkey:6379/0"}
  - secret: sneakers/sneakers-kratos
    keys:
      - {key: dsn, value: "postgres://sneakers:{sneakers-bundled/password}@sneakers-postgres:5432/k"}
      - {key: smtpConnectionURI, value: "smtp://smtp.example.org:25/"}
      - {key: cipher, generate: password}
  - secret: sneakers/sneakers-box
    keys:
      - {key: VAULT_ROOT_KEK, generate: key32}
      - {key: SETUP_TOKEN, generate: token}
`

// box_secrets are the Secrets the box makes for itself, once, on the box:
// generated values and values built from them.
func TestBoxSecretsParse(t *testing.T) {
	s, err := productspec.Parse([]byte(withBoxSecrets))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.BoxSecrets) != 3 || s.BoxSecrets[0].Namespace() != "sneakers" || s.BoxSecrets[0].SecretName() != "sneakers-bundled" {
		t.Fatalf("%+v", s.BoxSecrets)
	}
	k := s.BoxSecrets[0].Keys[2]
	if k.Key != "redis-url" || k.Generate != "" || !strings.Contains(k.Value, "{valkey-password}") {
		t.Fatalf("%+v", k)
	}
}

func TestBoxSecretsAreRefusedWhenTheyBreakARule(t *testing.T) {
	cases := map[string]string{
		"no namespace":          "{secret: s, keys: [{key: a, generate: password}]}",
		"no keys":               "{secret: ns/s, keys: []}",
		"a bad key":             "{secret: ns/s, keys: [{key: 'a b', generate: password}]}",
		"an unknown generator":  "{secret: ns/s, keys: [{key: a, generate: rot13}]}",
		"neither":               "{secret: ns/s, keys: [{key: a}]}",
		"both":                  "{secret: ns/s, keys: [{key: a, generate: password, value: x}]}",
		"a key twice":           "{secret: ns/s, keys: [{key: a, generate: password}, {key: a, generate: token}]}",
		"a ref to nothing":      "{secret: ns/s, keys: [{key: a, value: 'x{b}'}]}",
		"a ref to a value":      "{secret: ns/s, keys: [{key: b, value: lit}, {key: a, value: 'x{b}'}]}",
		"an unclosed brace":     "{secret: ns/s, keys: [{key: b, generate: password}, {key: a, value: 'x{b'}]}",
		"a ref to another ns":   "{secret: ns/s, keys: [{key: a, value: '{other/b}'}]}",
		"an unknown field":      "{secret: ns/s, keys: [{key: a, generate: password, length: 9}]}",
		"the appliance's stack": "{secret: sneakers-appliance/s, keys: [{key: a, generate: password}]}",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := productspec.Parse([]byte("format: 2\nbox_secrets:\n  - " + doc + "\n")); !codes.Is(err, codes.KitBundleMismatch) {
				t.Fatalf("err %v", err)
			}
		})
	}
	twice := "format: 2\nbox_secrets:\n  - {secret: ns/s, keys: [{key: a, generate: password}]}\n  - {secret: ns/s, keys: [{key: b, generate: password}]}\n"
	if _, err := productspec.Parse([]byte(twice)); !codes.Is(err, codes.KitBundleMismatch) {
		t.Fatalf("a secret twice: err %v", err)
	}
}

// The Sneakers bundle declares every Secret its stacks read as a box
// secret, so no value is baked into the bundle: the bundled pieces', the
// vault root key and TOTP key, and the setup token it exposes.
func TestTheSneakersBundleDeclaresItsBoxSecrets(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "product", "sneakers", "product.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := productspec.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, bs := range s.BoxSecrets {
		for _, k := range bs.Keys {
			have[bs.Secret+"/"+k.Key] = true
		}
	}
	for _, want := range []string{
		"sneakers/sneakers-bundled/password", "sneakers/sneakers-bundled/postgres-password", "sneakers/sneakers-bundled/valkey-password", "sneakers/sneakers-bundled/redis-url",
		"sneakers/sneakers-kratos/dsn", "sneakers/sneakers-kratos/secretsDefault", "sneakers/sneakers-kratos/secretsCookie", "sneakers/sneakers-kratos/secretsCipher", "sneakers/sneakers-kratos/smtpConnectionURI",
		"sneakers/sneakers-hydra/dsn", "sneakers/sneakers-hydra/secretsSystem", "sneakers/sneakers-hydra/secretsCookie",
		"sneakers/sneakers-box/VAULT_ROOT_KEK", "sneakers/sneakers-box/TOTP_ENC_KEY", "sneakers/sneakers-setup-token/SETUP_TOKEN",
	} {
		if !have[want] {
			t.Errorf("no box secret %s", want)
		}
	}
	v, _ := s.Find("setup-token")
	if !have[v.Secret+"/"+v.Key] {
		t.Errorf("the exposed setup token %s/%s isn't a box secret", v.Secret, v.Key)
	}
	// The keys the escrow carries are the ones the box made.
	for _, e := range s.Escrow {
		if !have[e.Secret+"/"+e.Key] {
			t.Errorf("the escrow key %s (%s/%s) isn't a box secret", e.Name, e.Secret, e.Key)
		}
	}
}

const withData = `format: 2
data:
  - name: database
    label: The database
    path: postgres
    wal: pgdata/pg_wal
    wal_warn: 1GiB
  - {name: cache, label: The cache, path: valkey}
`

// The product names its data paths, relative to the data root, and the
// write-ahead log under one with the size that's too big; the disk guard
// watches them for growth.
func TestTheDataPathsParse(t *testing.T) {
	s, err := productspec.Parse([]byte(withData))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Data) != 2 {
		t.Fatalf("%+v", s.Data)
	}
	db := s.Data[0]
	if db.HostPath() != productspec.DataRoot+"/postgres" || db.WAL != "pgdata/pg_wal" || db.WALWarnBytes() != 1<<30 {
		t.Fatalf("%+v %s %d", db, db.HostPath(), db.WALWarnBytes())
	}
	if s.Data[1].WALWarnBytes() != 0 {
		t.Fatalf("%+v", s.Data[1])
	}
}

func TestADataPathIsRefusedWhenItBreaksARule(t *testing.T) {
	for name, bad := range map[string]string{
		"no name":       "format: 2\ndata:\n  - {label: x, path: p}\n",
		"twice":         "format: 2\ndata:\n  - {name: a, label: A, path: p}\n  - {name: a, label: B, path: q}\n",
		"absolute path": "format: 2\ndata:\n  - {name: a, label: A, path: /var/lib/x}\n",
		"escaping path": "format: 2\ndata:\n  - {name: a, label: A, path: ../sneakers}\n",
		"escaping wal":  "format: 2\ndata:\n  - {name: a, label: A, path: p, wal: ../../x, wal_warn: 1GiB}\n",
		"bad size":      "format: 2\ndata:\n  - {name: a, label: A, path: p, wal: w, wal_warn: lots}\n",
		"size, no wal":  "format: 2\ndata:\n  - {name: a, label: A, path: p, wal_warn: 1GiB}\n",
		"wal, no size":  "format: 2\ndata:\n  - {name: a, label: A, path: p, wal: w}\n",
		"no label":      "format: 2\ndata:\n  - {name: a, path: p}\n",
		"unclean path":  "format: 2\ndata:\n  - {name: a, label: A, path: p//q}\n",
	} {
		if _, err := productspec.Parse([]byte(bad)); !codes.Is(err, codes.KitBundleMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The Sneakers bundle declares its database's data path and WAL limit.
func TestTheSneakersBundleDeclaresItsDataPaths(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "product", "sneakers", "product.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := productspec.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	var wal bool
	for _, d := range s.Data {
		if d.WAL != "" && d.WALWarnBytes() > 0 {
			wal = true
		}
	}
	if len(s.Data) == 0 || !wal {
		t.Fatalf("data %+v", s.Data)
	}
}

// The ready section: the product's own health check and how long the box
// waits for it; a bad service, path or timeout is refused.
func TestTheReadySectionParses(t *testing.T) {
	s, err := productspec.Parse([]byte("format: 2\nready:\n  health: {service: app/app-api:http, path: /readyz}\n  timeout: 15m\n"))
	if err != nil {
		t.Fatal(err)
	}
	h := s.Health()
	if h == nil || h.Namespace() != "app" || h.ProxyName() != "app-api:http" || h.Path != "/readyz" || s.ReadyTimeout() != 15*time.Minute {
		t.Fatalf("%+v %+v", h, s.ReadyTimeout())
	}
	if none, _ := productspec.Parse([]byte("format: 2\n")); none.Health() != nil || none.ReadyTimeout() != 0 {
		t.Fatal("no ready section declares a health check or a timeout")
	}
	for _, doc := range []string{
		"format: 2\nready:\n  health: {service: app-api, path: /readyz}\n",
		"format: 2\nready:\n  health: {service: app/app-api:http, path: ../readyz}\n",
		"format: 2\nready:\n  timeout: 10s\n",
		"format: 2\nready:\n  timeout: 3h\n",
		"format: 2\nready:\n  timeout: soon\n",
	} {
		if _, err := productspec.Parse([]byte(doc)); !codes.Is(err, codes.KitBundleMismatch) {
			t.Errorf("%q: %v", doc, err)
		}
	}
}

// The Sneakers bundle's product.yaml asks the gateway's readiness before an
// install counts as done.
func TestTheSneakersBundleDeclaresItsHealthCheck(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "build", "product", "sneakers", "product.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := productspec.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if h := s.Health(); h == nil || h.Service != "sneakers/sneakers-gateway:http" || h.Path != "/readyz" {
		t.Fatalf("%+v", h)
	}
}
