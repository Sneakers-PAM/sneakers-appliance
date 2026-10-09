// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package productspec reads a product bundle's product.yaml (bundle format
// v2): what the product declares to the appliance. Today that is its
// exposed values, the Secret values owners and admins may read from the
// closed shell's product section ("<product> <name>") without the root
// shell. The list is a strict allow-list: the appliance reads exactly the
// Secret keys named here, through its own service account, whose Role names
// those Secrets and may only get them. Nothing else is reachable, and the
// appliance holds no product's names in its code.
package productspec

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// File is product.yaml's name at the top of an unpacked bundle, and so in
// a product slot.
const File = "product.yaml"

// RBACFile is the RBAC the appliance renders for the declared values,
// written into the slot next to the bundle once it checks out. k0s applies
// it as the stack RBACStack.
const RBACFile = "exposed-rbac.yaml"

// RBACStack is the k0s stack the RBAC goes into; a bundle may not carry a
// stack of that name.
const RBACStack = "sneakers-appliance-exposed"

// Format is the product.yaml format this appliance reads.
const Format = 2

// Namespace and ServiceAccount are the appliance's own identity in the
// cluster, which reads the declared values.
const (
	Namespace      = "sneakers-appliance"
	ServiceAccount = "exposed-values"
)

// The roles an exposed value may name: the appliance's admin roles.
const (
	RoleOwner = "owner"
	RoleAdmin = "admin"
)

// Reserved are the product command words the appliance itself offers in a
// product's section; an exposed value can't take one.
var Reserved = []string{"mcp", "help"}

// Spec is product.yaml.
type Spec struct {
	Format        int            `yaml:"format"`
	ExposedValues []ExposedValue `yaml:"exposed_values"`
}

// ExposedValue is one Secret key a product lets the listed roles read.
type ExposedValue struct {
	// Name is the command word: "<product> <name>" in the shell.
	Name string `yaml:"name"`
	// Secret is <namespace>/<name>.
	Secret string `yaml:"secret"`
	// Key is the key in the Secret's data.
	Key   string   `yaml:"key"`
	Roles []string `yaml:"roles"`
	// OneTime values stop being shown once ConsumedWhen holds, for good.
	OneTime      bool    `yaml:"one_time"`
	ConsumedWhen *Signal `yaml:"consumed_when"`
	Label        string  `yaml:"label"`
	// Link is shown with the value; {host} becomes the box's host name.
	Link string `yaml:"link"`
}

// Signal is a product readiness or setup-done check: a GET through the API
// server's service proxy whose JSON answer has Field equal to Equals.
type Signal struct {
	// Service is <namespace>/<service>:<port name or number>.
	Service string `yaml:"service"`
	Path    string `yaml:"path"`
	Field   string `yaml:"field"`
	Equals  any    `yaml:"equals"`
}

var (
	nameRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	dnsRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	secretRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	keyRE     = regexp.MustCompile(`^[-._a-zA-Z0-9]{1,253}$`)
	portRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?$`)
	fieldRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	sigPathRE = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+$`)
)

func bad(format string, args ...any) error {
	return codes.New(codes.KitBundleMismatch, "product.yaml: "+format, args...)
}

// Parse reads and checks product.yaml.
func Parse(b []byte) (Spec, error) {
	var s Spec
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return Spec{}, bad("doesn't parse: %v", err)
	}
	if s.Format != Format {
		return Spec{}, bad("is format %d; this appliance reads format %d", s.Format, Format)
	}
	seen := map[string]bool{}
	for i, v := range s.ExposedValues {
		if err := v.check(); err != nil {
			return Spec{}, bad("exposed_values[%d]: %v", i, err)
		}
		if seen[v.Name] {
			return Spec{}, bad("exposed_values[%d]: %q is declared twice", i, v.Name)
		}
		seen[v.Name] = true
	}
	return s, nil
}

func (v ExposedValue) check() error {
	if !nameRE.MatchString(v.Name) {
		return fmt.Errorf("the name %q isn't a lower-case command word", v.Name)
	}
	if slices.Contains(Reserved, v.Name) {
		return fmt.Errorf("the name %q is one of the appliance's own product commands", v.Name)
	}
	ns, name, ok := strings.Cut(v.Secret, "/")
	if !ok || !dnsRE.MatchString(ns) || !secretRE.MatchString(name) {
		return fmt.Errorf("the secret %q isn't <namespace>/<name>", v.Secret)
	}
	if !keyRE.MatchString(v.Key) {
		return fmt.Errorf("the key %q isn't a Secret data key", v.Key)
	}
	if len(v.Roles) == 0 {
		return errors.New("no roles may read it")
	}
	for _, r := range v.Roles {
		if r != RoleOwner && r != RoleAdmin {
			return fmt.Errorf("the role %q isn't owner or admin", r)
		}
	}
	if v.OneTime && v.ConsumedWhen == nil {
		return errors.New("a one_time value says when it's consumed (consumed_when)")
	}
	if c := v.ConsumedWhen; c != nil {
		if err := c.check(); err != nil {
			return err
		}
	}
	if v.Link != "" {
		u, err := url.Parse(strings.ReplaceAll(v.Link, "{host}", "box.example.org"))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return fmt.Errorf("the link %q isn't an https:// URL", v.Link)
		}
	}
	return nil
}

func (c Signal) check() error {
	if _, _, _, ok := c.parts(); !ok {
		return fmt.Errorf("consumed_when.service %q isn't <namespace>/<service>:<port>", c.Service)
	}
	if !sigPathRE.MatchString(c.Path) || path.Clean(c.Path) != c.Path || strings.Contains(c.Path, "..") {
		return fmt.Errorf("consumed_when.path %q isn't a plain absolute path", c.Path)
	}
	if !fieldRE.MatchString(c.Field) {
		return fmt.Errorf("consumed_when.field %q isn't a JSON field name", c.Field)
	}
	switch c.Equals.(type) {
	case bool, string, int:
	default:
		return errors.New("consumed_when.equals is a boolean, a string or a whole number")
	}
	return nil
}

func (c Signal) parts() (ns, svc, port string, ok bool) {
	ns, rest, ok1 := strings.Cut(c.Service, "/")
	svc, port, ok2 := strings.Cut(rest, ":")
	if !ok1 || !ok2 || !dnsRE.MatchString(ns) || !dnsRE.MatchString(svc) || !portRE.MatchString(port) {
		return "", "", "", false
	}
	return ns, svc, port, true
}

// Namespace is the signal's namespace.
func (c Signal) Namespace() string { ns, _, _, _ := c.parts(); return ns }

// ProxyName is the service and port as the service proxy names them:
// <service>:<port>.
func (c Signal) ProxyName() string {
	_, svc, port, _ := c.parts()
	return svc + ":" + port
}

// Holds reports whether a decoded JSON answer meets the signal.
func (c Signal) Holds(answer map[string]any) bool {
	got, ok := answer[c.Field]
	if !ok {
		return false
	}
	switch want := c.Equals.(type) {
	case bool:
		b, ok := got.(bool)
		return ok && b == want
	case string:
		s, ok := got.(string)
		return ok && s == want
	case int:
		f, ok := got.(float64)
		return ok && f == float64(want)
	}
	return false
}

// Namespace is the Secret's namespace.
func (v ExposedValue) Namespace() string { ns, _, _ := strings.Cut(v.Secret, "/"); return ns }

// SecretName is the Secret's name.
func (v ExposedValue) SecretName() string { _, n, _ := strings.Cut(v.Secret, "/"); return n }

// Allows reports whether role may read the value.
func (v ExposedValue) Allows(role string) bool { return slices.Contains(v.Roles, role) }

// LinkFor is the link with {host} replaced; empty without a link or a
// host.
func (v ExposedValue) LinkFor(host string) string {
	if v.Link == "" || host == "" && strings.Contains(v.Link, "{host}") {
		return ""
	}
	return strings.ReplaceAll(v.Link, "{host}", host)
}

// Find returns the value declared under name.
func (s Spec) Find(name string) (ExposedValue, bool) {
	for _, v := range s.ExposedValues {
		if v.Name == name {
			return v, true
		}
	}
	return ExposedValue{}, false
}

// Load reads dir/product.yaml; a bundle without one declares nothing.
func Load(dir string) (Spec, error) {
	b, err := os.ReadFile(filepath.Join(dir, File)) // #nosec G304 -- a product slot's own file
	if errors.Is(err, fs.ErrNotExist) {
		return Spec{Format: Format}, nil
	}
	if err != nil {
		return Spec{}, fmt.Errorf("productspec: %w", err)
	}
	return Parse(b)
}

// Check checks product.yaml in an unpacked bundle, when there is one.
func Check(fsys fs.FS) error {
	b, err := fs.ReadFile(fsys, File)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return bad("can't be read: %v", err)
	}
	_, err = Parse(b)
	return err
}

// RBAC renders the k0s stack for s: the appliance's namespace and service
// account and, per namespace the values live in, a Role that may only get
// the declared Secrets (and the declared signals' service proxies) by name,
// bound to that service account. No ClusterRole, no list or watch.
func RBAC(s Spec) []byte {
	secrets := map[string][]string{}
	proxies := map[string][]string{}
	for _, v := range s.ExposedValues {
		secrets[v.Namespace()] = appendNew(secrets[v.Namespace()], v.SecretName())
		if c := v.ConsumedWhen; c != nil {
			proxies[c.Namespace()] = appendNew(proxies[c.Namespace()], c.ProxyName())
		}
	}
	nss := map[string]bool{}
	for ns := range secrets {
		nss[ns] = true
	}
	for ns := range proxies {
		nss[ns] = true
	}
	order := make([]string, 0, len(nss))
	for ns := range nss {
		order = append(order, ns)
	}
	sort.Strings(order)
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n", Namespace)
	fmt.Fprintf(&b, "---\napiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: %s\n  namespace: %s\nautomountServiceAccountToken: false\n", ServiceAccount, Namespace)
	for _, ns := range order {
		fmt.Fprintf(&b, "---\napiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: %s\n  namespace: %s\nrules:\n", RBACStack, ns)
		if names := secrets[ns]; len(names) > 0 {
			sort.Strings(names)
			fmt.Fprintf(&b, "  - apiGroups: [\"\"]\n    resources: [secrets]\n    resourceNames: [%s]\n    verbs: [get]\n", quoted(names))
		}
		if names := proxies[ns]; len(names) > 0 {
			sort.Strings(names)
			fmt.Fprintf(&b, "  - apiGroups: [\"\"]\n    resources: [services/proxy]\n    resourceNames: [%s]\n    verbs: [get]\n", quoted(names))
		}
		fmt.Fprintf(&b, "---\napiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: %s\n  namespace: %s\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: Role\n  name: %s\nsubjects:\n  - kind: ServiceAccount\n    name: %s\n    namespace: %s\n", RBACStack, ns, RBACStack, ServiceAccount, Namespace)
	}
	return []byte(b.String())
}

func appendNew(list []string, v string) []string {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

func quoted(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = `"` + n + `"`
	}
	return strings.Join(q, ", ")
}

// WriteRBAC renders the RBAC for the product.yaml in slot dir into
// dir/RBACFile; a bundle that exposes nothing gets none.
func WriteRBAC(dir string) error {
	s, err := Load(dir)
	if err != nil {
		return err
	}
	p := filepath.Join(dir, RBACFile)
	if len(s.ExposedValues) == 0 {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("productspec: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(p, RBAC(s), 0o644); err != nil { // #nosec G306 -- RBAC, nothing secret; k0s reads the slot as root
		return fmt.Errorf("productspec: %w", err)
	}
	return nil
}
