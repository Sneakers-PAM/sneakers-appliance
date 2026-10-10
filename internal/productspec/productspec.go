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
	"strconv"
	"strings"
	"time"

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

// SwitchStacksFile is written into the slot next to the bundle: one line
// per stack a switch gates, "<switch> <stack> <on|off default>", for
// k0s-interim.
const SwitchStacksFile = "switch-stacks"

// Spec is product.yaml.
type Spec struct {
	Format        int            `yaml:"format"`
	ExposedValues []ExposedValue `yaml:"exposed_values"`
	// Components are what every bundle of the product must carry, each
	// named by its image's last path element; the bundle check refuses a
	// bundle without one.
	Components []Component `yaml:"components"`
	// Switches turn parts of the product on and off from :8443: each
	// gates its own stacks, which k0s applies only while it's on.
	Switches []Switch `yaml:"switches"`
	// Import, when set, lets the product take an export of an earlier
	// install from the Import page before its own first-run setup.
	Import *Import `yaml:"import"`
	// Escrow are the keys the product's data can't be opened without (a
	// vault's root key, say). The box seals each under KeyCustody, so the
	// recovery escrow carries them for a restore onto another box.
	Escrow []EscrowKey `yaml:"escrow"`
	// BoxValues are the values of the box itself the product's stacks
	// read, such as its host name: each stack carries a placeholder that
	// the box replaces with its own value when it puts the stack in front
	// of k0s, so no bundle names a box (package boxvalues).
	BoxValues []BoxValue `yaml:"box_values"`
	// BoxSecrets are the Secrets the box makes for itself on the box
	// (package boxsecrets): no bundle carries their values, so every box
	// has its own, kept across updates and reverts.
	BoxSecrets []BoxSecret `yaml:"box_secrets"`
	// BoxSettings are ConfigMaps the box writes from the settings an
	// admin sets on :8443 (package boxsettings), never secret ones.
	BoxSettings []BoxSetting `yaml:"box_settings"`
	// Email, when set, says the product reads the box's email settings,
	// so :8443 offers its Email page.
	Email *Email `yaml:"email"`
	// Data are the product's data paths the box watches for growth (the
	// disk guard): each a directory under DataRoot, optionally with the
	// write-ahead log under it and the size that's too big.
	Data []DataPath `yaml:"data"`
	// Ready, when set, says how the box knows the product is ready after
	// an install, an update or a revert: the product's own health check,
	// and how long the box waits for it (docs/upgrades.md).
	Ready *Ready `yaml:"ready"`
	// Phases, when set, are the order the product comes up in, each
	// gated on Ready before the next (phases.go, docs/upgrades.md).
	Phases []Phase `yaml:"phases"`
}

// Ready is product.yaml's ready section.
type Ready struct {
	// Health is a GET through the API server's service proxy that answers
	// 2xx once the product is ready (its readiness endpoint, say).
	Health *HealthCheck `yaml:"health"`
	// Timeout is how long an install, update or revert may take to be
	// ready, a duration such as "15m" between MinReadyTimeout and
	// MaxReadyTimeout; empty is the box's default.
	Timeout string `yaml:"timeout"`
}

// HealthCheck is a GET of Path on Service through the service proxy.
type HealthCheck struct {
	// Service is <namespace>/<service>:<port name or number>.
	Service string `yaml:"service"`
	Path    string `yaml:"path"`
}

// The bounds of ready.timeout.
const (
	MinReadyTimeout = time.Minute
	MaxReadyTimeout = 2 * time.Hour
)

// Namespace is the health check's namespace.
func (h HealthCheck) Namespace() string { return Signal{Service: h.Service}.Namespace() }

// ProxyName is the service and port as the service proxy names them.
func (h HealthCheck) ProxyName() string { return Signal{Service: h.Service}.ProxyName() }

// Health is the product's health check, or nil when it declares none.
func (s Spec) Health() *HealthCheck {
	if s.Ready == nil {
		return nil
	}
	return s.Ready.Health
}

// ReadyTimeout is ready.timeout, or 0 when it isn't set.
func (s Spec) ReadyTimeout() time.Duration {
	if s.Ready == nil || s.Ready.Timeout == "" {
		return 0
	}
	d, _ := time.ParseDuration(s.Ready.Timeout)
	return d
}

func (s Spec) checkReady() error {
	if s.Ready == nil {
		return nil
	}
	if h := s.Ready.Health; h != nil {
		if _, _, _, ok := (Signal{Service: h.Service}).parts(); !ok {
			return bad("ready.health.service %q isn't <namespace>/<service>:<port>", h.Service)
		}
		if !sigPathRE.MatchString(h.Path) || path.Clean(h.Path) != h.Path || strings.Contains(h.Path, "..") {
			return bad("ready.health.path %q isn't a plain absolute path", h.Path)
		}
	}
	if t := s.Ready.Timeout; t != "" {
		d, err := time.ParseDuration(t)
		if err != nil || d < MinReadyTimeout || d > MaxReadyTimeout {
			return bad("ready.timeout %q isn't a duration from %s to %s", t, MinReadyTimeout, MaxReadyTimeout)
		}
	}
	return nil
}

// DataRoot is where a product's volumes live on the box: every volume
// claim in a bundle's stacks becomes a hostPath under it.
const DataRoot = "/var/lib/sneakers-data"

// DataPath is one product data directory.
type DataPath struct {
	Name  string `yaml:"name"`
	Label string `yaml:"label"`
	// Path is relative to DataRoot.
	Path string `yaml:"path"`
	// WAL is the write-ahead log's directory, relative to Path, and
	// WALWarn the size it shouldn't pass, such as 1GiB.
	WAL     string `yaml:"wal"`
	WALWarn string `yaml:"wal_warn"`
}

// HostPath is the directory on the box.
func (d DataPath) HostPath() string { return path.Join(DataRoot, d.Path) }

// WALWarnBytes is WALWarn in bytes, 0 when unset.
func (d DataPath) WALWarnBytes() int64 {
	n, _ := parseSize(d.WALWarn)
	return n
}

var sizeRE = regexp.MustCompile(`^([1-9][0-9]{0,5})(KiB|MiB|GiB|TiB)$`)

func parseSize(s string) (int64, bool) {
	m := sizeRE.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	shift := map[string]uint{"KiB": 10, "MiB": 20, "GiB": 30, "TiB": 40}[m[2]]
	return n << shift, true
}

// relPath reports whether p is a clean relative path that stays inside
// the directory it's relative to.
func relPath(p string) bool {
	return p != "" && !path.IsAbs(p) && path.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../")
}

func (s Spec) checkData() error {
	seen := map[string]bool{}
	for i, d := range s.Data {
		switch {
		case !nameRE.MatchString(d.Name) || seen[d.Name]:
			return bad("data[%d]: %q isn't a lower-case word, or is declared twice", i, d.Name)
		case d.Label == "":
			return bad("data[%d]: %s has no label", i, d.Name)
		case !relPath(d.Path):
			return bad("data[%d]: the path %q isn't a clean path under the data root", i, d.Path)
		case (d.WAL == "") != (d.WALWarn == ""):
			return bad("data[%d]: a write-ahead log needs both wal and wal_warn", i)
		case d.WAL != "" && !relPath(d.WAL):
			return bad("data[%d]: the write-ahead log %q isn't a clean path under %s", i, d.WAL, d.Path)
		}
		if _, ok := parseSize(d.WALWarn); d.WALWarn != "" && !ok {
			return bad("data[%d]: wal_warn %q isn't a size such as 1GiB", i, d.WALWarn)
		}
		seen[d.Name] = true
	}
	return nil
}

// EscrowKey is one Secret key the recovery escrow carries.
type EscrowKey struct {
	// Name is the key's name in the escrow, a lower-case word.
	Name string `yaml:"name"`
	// Secret is <namespace>/<name>.
	Secret string `yaml:"secret"`
	// Key is the key in the Secret's data.
	Key string `yaml:"key"`
}

// Namespace is the Secret's namespace.
func (e EscrowKey) Namespace() string { ns, _, _ := strings.Cut(e.Secret, "/"); return ns }

// SecretName is the Secret's name.
func (e EscrowKey) SecretName() string { _, n, _ := strings.Cut(e.Secret, "/"); return n }

func (s Spec) checkEscrow() error {
	seen := map[string]bool{}
	for i, e := range s.Escrow {
		ns, name, ok := strings.Cut(e.Secret, "/")
		switch {
		case !nameRE.MatchString(e.Name) || seen[e.Name]:
			return bad("escrow[%d]: %q isn't a lower-case word, or is named twice", i, e.Name)
		case !ok || !dnsRE.MatchString(ns) || !secretRE.MatchString(name):
			return bad("escrow[%d]: the secret %q isn't <namespace>/<name>", i, e.Secret)
		case !keyRE.MatchString(e.Key):
			return bad("escrow[%d]: the key %q isn't a Secret data key", i, e.Key)
		}
		seen[e.Name] = true
	}
	return nil
}

// Import is how the product takes an export of an earlier install
// (docs/import.md). The box keeps the export, its key and each step's
// output in a directory of the state volume, and runs each step as a Job
// from the bundle's template, in the stack of Switch, which is on only
// while an import is open.
type Import struct {
	Label string `yaml:"label"`
	// Switch gates the import's stack: the migrate service account and the
	// policies that admit it exist only while an import is open.
	Switch string `yaml:"switch"`
	// Job is the Job template, relative to the slot. The box fills
	// ${JOB_NAME}, ${ARGS} (the command's arguments as a JSON list) and
	// ${HOST_DIR} (the import directory, which the Job mounts).
	Job string `yaml:"job"`
	// UID owns the import directory and its files: the Job's user.
	UID int `yaml:"uid"`
	// Setup is the one-time exposed value the product's own first-run
	// setup consumes: once it's consumed, and the box hasn't imported, no
	// import opens. An imported box treats it as consumed.
	Setup string `yaml:"setup"`
	// Restart are the workloads restarted after an import, so they load
	// what it wrote.
	Restart []string `yaml:"restart"`
	// After, with phases, is the phase the product holds after while an
	// import is open: the phases through it run (what the import writes
	// to), the later ones are stopped until it's closed, and the box says
	// maintenance meanwhile.
	After string `yaml:"after"`
}

var jobRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*\.ya?ml$`)

// ImportStack is the stack the import switch gates.
func (s Spec) ImportStack() (string, bool) {
	if s.Import == nil {
		return "", false
	}
	w, ok := s.Switch(s.Import.Switch)
	if !ok || len(w.Stacks) == 0 {
		return "", false
	}
	return w.Stacks[0], true
}

// RestartRef splits Restart[i].
func (im Import) RestartRef(i int) (ns, kind, name string, ok bool) {
	return Switch{Restart: im.Restart}.RestartRef(i)
}

func (s Spec) checkImport() error {
	im := s.Import
	if im == nil {
		return nil
	}
	if _, ok := s.ImportStack(); !ok {
		return bad("import: the switch %q isn't declared", im.Switch)
	}
	if !jobRE.MatchString(im.Job) || strings.Contains(im.Job, "..") {
		return bad("import: the job %q isn't a .yaml path inside the slot", im.Job)
	}
	if im.UID < 1 || im.UID > 65535 {
		return bad("import: the uid %d isn't a non-root user id", im.UID)
	}
	if v, ok := s.Find(im.Setup); !ok || !v.OneTime {
		return bad("import: setup %q isn't a one_time exposed value", im.Setup)
	}
	for j := range im.Restart {
		if _, _, _, ok := im.RestartRef(j); !ok {
			return bad("import: %q isn't <namespace>/<deployment|statefulset|daemonset>/<name>", im.Restart[j])
		}
	}
	return nil
}

// BoxValuesFile is written into the slot next to the bundle: one line per
// box value the stacks read, "<placeholder> <value>", for k0s-interim and
// productswitch.
const BoxValuesFile = "box-values"

// The box values the box offers (package boxvalues says where each comes
// from): its fully qualified host name, and the versions of the Base OS it
// runs and the Base Web it serves.
const (
	BoxFQDN       = "box.fqdn"
	BoxOSVersion  = "box.os.version"
	BoxWebVersion = "box.web.version"
)

// boxValuesOffered are the box values a bundle may declare.
var boxValuesOffered = []string{BoxFQDN, BoxOSVersion, BoxWebVersion}

// BoxValue is one box value a product's stacks read, by placeholder.
type BoxValue struct {
	Value string `yaml:"value"`
	// Placeholder is a name under the reserved .invalid top-level domain
	// (RFC 6761), which never resolves and so can't be mistaken for a real
	// host if one is ever left in place.
	Placeholder string `yaml:"placeholder"`
}

// BoxSecretsStack is the k0s stack the box secrets go into; a bundle may
// not carry a stack of that name.
const BoxSecretsStack = "sneakers-appliance-secrets"

// The generators a box secret key may name.
const (
	// GeneratePassword is 32 letters and digits.
	GeneratePassword = "password"
	// GenerateKey32 is 32 random bytes, standard base64.
	GenerateKey32 = "key32"
	// GenerateToken is 32 random bytes, URL-safe base64 without padding.
	GenerateToken = "token"
)

// BoxSecret is one Secret the box makes.
type BoxSecret struct {
	// Secret is <namespace>/<name>.
	Secret string   `yaml:"secret"`
	Keys   []BoxKey `yaml:"keys"`
}

// BoxKey is one key of a box secret: generated once (Generate), or a value
// (Value) that may name generated keys as {key} (this Secret's) or
// {secret/key} (another box secret's in the same namespace).
type BoxKey struct {
	Key      string `yaml:"key"`
	Generate string `yaml:"generate"`
	Value    string `yaml:"value"`
	// Setting is one of the box's settings (productspec.IsSetting), set
	// on :8443; unset, its default.
	Setting string `yaml:"setting"`
}

// Namespace is the Secret's namespace.
func (b BoxSecret) Namespace() string { ns, _, _ := strings.Cut(b.Secret, "/"); return ns }

// SecretName is the Secret's name.
func (b BoxSecret) SecretName() string { _, n, _ := strings.Cut(b.Secret, "/"); return n }

// Refs splits a box key's value into literal text and references, in
// order: each reference is resolved to <namespace>/<secret>/<key>.
func (b BoxSecret) Refs(value string) (parts []string, refs []bool, err error) {
	for value != "" {
		i := strings.IndexAny(value, "{}")
		if i < 0 {
			parts, refs = append(parts, value), append(refs, false)
			break
		}
		if value[i] == '}' {
			return nil, nil, errors.New("a } without a {")
		}
		if i > 0 {
			parts, refs = append(parts, value[:i]), append(refs, false)
		}
		j := strings.IndexByte(value[i:], '}')
		if j < 0 {
			return nil, nil, errors.New("a { without a }")
		}
		ref := value[i+1 : i+j]
		secret, key, other := strings.Cut(ref, "/")
		if !other {
			secret, key = b.SecretName(), ref
		}
		if !secretRE.MatchString(secret) || !keyRE.MatchString(key) {
			return nil, nil, fmt.Errorf("{%s} isn't {key} or {secret/key}", ref)
		}
		parts, refs = append(parts, b.Namespace()+"/"+secret+"/"+key), append(refs, true)
		value = value[i+j+1:]
	}
	return parts, refs, nil
}

// Component is one part of the product the bundle must carry.
type Component struct {
	Name  string `yaml:"name"`
	Image string `yaml:"image"`
}

// Switch is a part of the product an admin turns on and off.
type Switch struct {
	Name    string `yaml:"name"`
	Label   string `yaml:"label"`
	Default bool   `yaml:"default"`
	// Stacks are the bundle's stacks applied only while it's on.
	Stacks []string `yaml:"stacks"`
	// Restart are workloads restarted after a change,
	// <namespace>/<deployment|statefulset|daemonset>/<name>, so they read
	// what the stacks bring or take away.
	Restart []string `yaml:"restart"`
}

var (
	restartRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)/(deployment|statefulset|daemonset)/([a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?)$`)
	stackRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
	imageRE   = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,127})$`)
)

// RestartRef splits Restart[i].
func (w Switch) RestartRef(i int) (ns, kind, name string, ok bool) {
	m := restartRE.FindStringSubmatch(w.Restart[i])
	if m == nil {
		return "", "", "", false
	}
	return m[1], m[3], m[4], true
}

// Switch returns the switch named name.
func (s Spec) Switch(name string) (Switch, bool) {
	for _, w := range s.Switches {
		if w.Name == name {
			return w, true
		}
	}
	return Switch{}, false
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
	if err := s.checkParts(); err != nil {
		return Spec{}, err
	}
	if err := s.checkBoxSecrets(); err != nil {
		return Spec{}, err
	}
	if err := s.checkSettings(); err != nil {
		return Spec{}, err
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
	if err := s.checkImport(); err != nil {
		return Spec{}, err
	}
	if err := s.checkEscrow(); err != nil {
		return Spec{}, err
	}
	if err := s.checkData(); err != nil {
		return Spec{}, err
	}
	if err := s.checkReady(); err != nil {
		return Spec{}, err
	}
	if err := s.checkPhases(); err != nil {
		return Spec{}, err
	}
	return s, nil
}

func (s Spec) checkParts() error {
	for i, c := range s.Components {
		if c.Name == "" || !imageRE.MatchString(c.Image) {
			return bad("components[%d]: a component has a name and its image's last path element", i)
		}
	}
	names, stacks := map[string]bool{}, map[string]bool{}
	for i, w := range s.Switches {
		if !nameRE.MatchString(w.Name) || names[w.Name] {
			return bad("switches[%d]: %q isn't a lower-case word, or is declared twice", i, w.Name)
		}
		names[w.Name] = true
		if len(w.Stacks) == 0 {
			return bad("switches[%d]: %s gates no stack", i, w.Name)
		}
		for _, st := range w.Stacks {
			if !stackRE.MatchString(st) || stacks[st] {
				return bad("switches[%d]: the stack %q isn't a stack name, or another switch gates it", i, st)
			}
			stacks[st] = true
		}
		for j := range w.Restart {
			if _, _, _, ok := w.RestartRef(j); !ok {
				return bad("switches[%d]: %q isn't <namespace>/<deployment|statefulset|daemonset>/<name>", i, w.Restart[j])
			}
		}
	}
	return s.checkBoxValues()
}

var placeholderRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+invalid$`)

func (s Spec) checkBoxValues() error {
	seen := map[string]bool{}
	for i, v := range s.BoxValues {
		if !slices.Contains(boxValuesOffered, v.Value) {
			return bad("box_values[%d]: %q isn't a box value this appliance offers (%s)", i, v.Value, strings.Join(boxValuesOffered, ", "))
		}
		if seen[v.Value] {
			return bad("box_values[%d]: %s is declared twice", i, v.Value)
		}
		seen[v.Value] = true
		if !placeholderRE.MatchString(v.Placeholder) {
			return bad("box_values[%d]: the placeholder %q isn't a lower-case name under .invalid", i, v.Placeholder)
		}
	}
	// Each placeholder is replaced as plain text, so none may hold another.
	for i, a := range s.BoxValues {
		for j, b := range s.BoxValues {
			if i != j && strings.Contains(a.Placeholder, b.Placeholder) {
				return bad("box_values[%d]: the placeholder %q holds box_values[%d]'s %q", i, a.Placeholder, j, b.Placeholder)
			}
		}
	}
	return nil
}

func (s Spec) checkBoxSecrets() error {
	generated := map[string]bool{}
	secrets := map[string]bool{}
	for i, b := range s.BoxSecrets {
		ns, name, ok := strings.Cut(b.Secret, "/")
		if !ok || !dnsRE.MatchString(ns) || !secretRE.MatchString(name) {
			return bad("box_secrets[%d]: the secret %q isn't <namespace>/<name>", i, b.Secret)
		}
		if ns == Namespace {
			return bad("box_secrets[%d]: %s is the appliance's own namespace", i, ns)
		}
		if secrets[b.Secret] {
			return bad("box_secrets[%d]: %s is declared twice", i, b.Secret)
		}
		secrets[b.Secret] = true
		if len(b.Keys) == 0 {
			return bad("box_secrets[%d]: %s has no keys", i, b.Secret)
		}
		keys := map[string]bool{}
		for j, k := range b.Keys {
			if !keyRE.MatchString(k.Key) || keys[k.Key] {
				return bad("box_secrets[%d].keys[%d]: %q isn't a Secret data key, or is declared twice", i, j, k.Key)
			}
			keys[k.Key] = true
			kinds := 0
			for _, v := range []string{k.Generate, k.Value, k.Setting} {
				if v != "" {
					kinds++
				}
			}
			switch {
			case kinds != 1:
				return bad("box_secrets[%d].keys[%d]: %s is generated, a value or a setting, one of them", i, j, k.Key)
			case k.Generate != "":
				switch k.Generate {
				case GeneratePassword, GenerateKey32, GenerateToken:
				default:
					return bad("box_secrets[%d].keys[%d]: the generator %q isn't %s, %s or %s", i, j, k.Generate, GeneratePassword, GenerateKey32, GenerateToken)
				}
				generated[b.Secret+"/"+k.Key] = true
			}
		}
	}
	for i, b := range s.BoxSecrets {
		for j, k := range b.Keys {
			if k.Value == "" {
				continue
			}
			parts, refs, err := b.Refs(k.Value)
			if err != nil {
				return bad("box_secrets[%d].keys[%d]: %s: %v", i, j, k.Key, err)
			}
			for n, p := range parts {
				if refs[n] && !generated[p] {
					return bad("box_secrets[%d].keys[%d]: %s names %s, which isn't a generated box secret key", i, j, k.Key, p)
				}
			}
		}
	}
	return nil
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
	for _, e := range s.Escrow {
		secrets[e.Namespace()] = appendNew(secrets[e.Namespace()], e.SecretName())
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
// dir/RBACFile (a bundle that exposes nothing gets none), and the
// stacks its switches gate into dir/SwitchStacksFile, and the box values
// its stacks read into dir/BoxValuesFile, and its phase stacks into
// dir/PhaseStacksFile.
func WriteRBAC(dir string) error {
	s, err := Load(dir)
	if err != nil {
		return err
	}
	if err := writeSwitchStacks(dir, s); err != nil {
		return err
	}
	if err := writeBoxValues(dir, s); err != nil {
		return err
	}
	if err := writePhaseStacks(dir, s); err != nil {
		return err
	}
	p := filepath.Join(dir, RBACFile)
	if len(s.ExposedValues) == 0 && len(s.Escrow) == 0 {
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

func writeBoxValues(dir string, s Spec) error {
	p := filepath.Join(dir, BoxValuesFile)
	if len(s.BoxValues) == 0 {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("productspec: %w", err)
		}
		return nil
	}
	var b strings.Builder
	for _, v := range s.BoxValues {
		fmt.Fprintf(&b, "%s %s\n", v.Placeholder, v.Value)
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil { // #nosec G306 -- placeholder names, nothing secret
		return fmt.Errorf("productspec: %w", err)
	}
	return nil
}

func writeSwitchStacks(dir string, s Spec) error {
	p := filepath.Join(dir, SwitchStacksFile)
	if len(s.Switches) == 0 {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("productspec: %w", err)
		}
		return nil
	}
	var b strings.Builder
	for _, w := range s.Switches {
		def := "off"
		if w.Default {
			def = "on"
		}
		for _, st := range w.Stacks {
			fmt.Fprintf(&b, "%s %s %s\n", w.Name, st, def)
		}
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil { // #nosec G306 -- stack names, nothing secret
		return fmt.Errorf("productspec: %w", err)
	}
	return nil
}
