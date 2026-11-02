// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package boxsecrets makes the Secrets a product's product.yaml declares as
// box_secrets, on the box: every generated value is made once, from the
// kernel's random source, and kept on the state volume, so no bundle carries
// a secret value, no two boxes share one, and updates and reverts keep them.
// Each product apply or revert writes the Secrets the current slot's bundle
// declares as the k0s stack productspec.BoxSecretsStack. INTERIM: platformd
// seals them through KeyCustody instead when it lands (#100).
package boxsecrets

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	"gopkg.in/yaml.v3"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/boxsettings"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// ValuesFile keeps every generated value, "<namespace>/<secret>/<key>" to
// the value, in Store.Dir (mode 0600).
const ValuesFile = "box-secrets.json"

// Store is the box's own Secrets.
type Store struct {
	// Dir is the platform settings directory (/var/lib/sneakers/platform).
	Dir string
	// Manifests is k0s's manifests directory (/var/lib/k0s/manifests).
	Manifests string
	// Settings are the box's settings an admin sets on :8443
	// (boxsettings.Store on the box); nil gives every setting its default.
	Settings Settings
	// Restore reads a product key the bundle names under escrow from the
	// box's sealed items, by its escrow name: on a replacement box they
	// came over with the escrow (KeyCustody.ImportEscrow), and a key made
	// anew would leave the restored data unreadable. found is false when
	// nothing is sealed under that name; nil restores nothing.
	Restore func(name string) (value string, found bool, err error)
	Logger  log.Logger
	// Now is the clock for certificates; nil is time.Now.
	Now func() time.Time
}

// A box certificate lasts ten years and is renewed at the first apply or
// revert in its last year. Nothing in between can miss a renewal: the
// box's clients ask for TLS and don't check the certificate's dates.
const (
	CertificateLifetime    = 10 * 365 * 24 * time.Hour
	CertificateRenewBefore = 365 * 24 * time.Hour
)

// Settings are the box's settings by name (productspec.IsSetting).
type Settings interface {
	Values() (map[string]string, error)
}

// RevisionAnnotation is on every object of the stack: a digest of what the
// stack carries, so the box can tell when k0s has applied a change.
const RevisionAnnotation = "sneakers-appliance/revision"

func (s *Store) settings() (map[string]string, error) {
	if s.Settings == nil {
		return boxsettings.DefaultEmail().Values(), nil
	}
	return s.Settings.Values()
}

func (s *Store) logger() log.Logger {
	if s.Logger == nil {
		return log.Nop()
	}
	return s.Logger
}

// Ensure makes the box secrets the bundle in slot declares, keeping every
// value made before, and writes them as the stack; a bundle that declares
// none leaves no stack. No value is logged.
func (s *Store) Ensure(slot string) error {
	spec, err := productspec.Load(slot)
	if err != nil {
		return err
	}
	stack := filepath.Join(s.Manifests, productspec.BoxSecretsStack)
	if len(spec.BoxSecrets) == 0 && len(spec.BoxSettings) == 0 {
		if err := os.RemoveAll(stack); err != nil {
			return fmt.Errorf("boxsecrets: %w", err)
		}
		s.logger().Info("boxsecrets: the product declares no box secrets; their stack goes")
		return nil
	}
	values, err := s.load()
	if err != nil {
		return err
	}
	made, restored := 0, 0
	for _, b := range spec.BoxSecrets {
		if b.Certificate != nil {
			issued, err := s.certificate(b, values)
			if err != nil {
				return err
			}
			if issued {
				made++
			}
			continue
		}
		for _, k := range b.Keys {
			id := b.Secret + "/" + k.Key
			if k.Generate == "" || values[id] != "" {
				continue
			}
			if name, ok := escrowName(spec, b.Secret, k.Key); ok && s.Restore != nil {
				v, found, err := s.Restore(name)
				if err != nil {
					return fmt.Errorf("boxsecrets: the escrowed %s can't be read, so no new one is made: %w", name, err)
				}
				if found {
					values[id] = v
					restored++
					s.logger().Info("boxsecrets: a key is restored from the escrow", log.F("key", name))
					continue
				}
			}
			v, err := generate(k.Generate)
			if err != nil {
				return err
			}
			values[id] = v
			made++
		}
	}
	if made > 0 || restored > 0 {
		if err := s.save(values); err != nil {
			return err
		}
	}
	settings, err := s.settings()
	if err != nil {
		return err
	}
	doc, err := RenderAll(spec, values, settings)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stack, 0o700); err != nil {
		return fmt.Errorf("boxsecrets: %w", err)
	}
	if err := writeAtomic(filepath.Join(stack, productspec.BoxSecretsStack+".yaml"), doc); err != nil {
		return err
	}
	s.logger().Info("boxsecrets: the box secrets are in place", log.F("secrets", len(spec.BoxSecrets)), log.F("generated", made), log.F("restored", restored))
	return nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// certificate issues b's certificate when the box has none, the one it has
// is in its last year, or the bundle names other hosts. The old one goes
// with its key: nothing but this Secret ever trusted it.
func (s *Store) certificate(b productspec.BoxSecret, values map[string]string) (bool, error) {
	id := func(k string) string { return b.Secret + "/" + k }
	now := s.now()
	if certCurrent(values[id(productspec.CertKey)], *b.Certificate, now) {
		return false, nil
	}
	crt, key, err := certstore.NewInternal(b.Certificate.CommonName, b.Certificate.DNSNames, CertificateLifetime, now)
	if err != nil {
		return false, fmt.Errorf("boxsecrets: %w", err)
	}
	values[id(productspec.CertKey)], values[id(productspec.PrivKey)], values[id(productspec.CAKey)] = string(crt), string(key), string(crt)
	s.logger().Info("boxsecrets: a certificate is issued", log.F("secret", b.Secret))
	return true, nil
}

func certCurrent(certPEM string, want productspec.BoxCertificate, now time.Time) bool {
	blk, _ := pem.Decode([]byte(certPEM))
	if blk == nil {
		return false
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return false
	}
	return c.NotAfter.Sub(now) > CertificateRenewBefore && slices.Equal(c.DNSNames, want.DNSNames) && c.Subject.CommonName == want.CommonName
}

// escrowName is the escrow name of a box secret's key, when the bundle
// names it under escrow.
func escrowName(spec productspec.Spec, secret, key string) (string, bool) {
	for _, e := range spec.Escrow {
		if e.Secret == secret && e.Key == key {
			return e.Name, true
		}
	}
	return "", false
}

// Render is the stack for spec's box secrets with values and the box's
// settings at their defaults.
func Render(spec productspec.Spec, values map[string]string) ([]byte, error) {
	return RenderAll(spec, values, boxsettings.DefaultEmail().Values())
}

// RenderAll is the stack for spec's box secrets with values, and its box
// settings with settings: each namespace they live in, then each Secret
// and each ConfigMap with its keys in order. Every object carries the
// stack's revision.
func RenderAll(spec productspec.Spec, values, settings map[string]string) ([]byte, error) {
	var nsOrder []string
	nss := map[string]bool{}
	addNS := func(ns string) {
		if !nss[ns] {
			nss[ns] = true
			nsOrder = append(nsOrder, ns)
		}
	}
	for _, b := range spec.BoxSecrets {
		addNS(b.Namespace())
	}
	for _, b := range spec.BoxSettings {
		addNS(b.Namespace())
	}
	type object struct {
		kind, ns, name, field string
		data                  *yaml.Node
	}
	var objs []object
	digest := sha256.New()
	pair := func(data *yaml.Node, k, v string) {
		data.Content = append(data.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Value: v, Style: yaml.DoubleQuotedStyle})
		_, _ = fmt.Fprintf(digest, "%d:%s%d:%s", len(k), k, len(v), v)
	}
	for _, b := range spec.BoxSecrets {
		data := &yaml.Node{Kind: yaml.MappingNode}
		_, _ = fmt.Fprintf(digest, "Secret/%s\n", b.Secret)
		if b.Certificate != nil {
			for _, k := range b.KeyNames() {
				v, ok := values[b.Secret+"/"+k]
				if !ok {
					return nil, fmt.Errorf("boxsecrets: %s has no %s", b.Secret, k)
				}
				pair(data, k, v)
			}
		}
		for _, k := range b.Keys {
			v, err := value(b, k, values, settings)
			if err != nil {
				return nil, err
			}
			pair(data, k.Key, v)
		}
		objs = append(objs, object{"Secret", b.Namespace(), b.SecretName(), "stringData", data})
	}
	for _, b := range spec.BoxSettings {
		data := &yaml.Node{Kind: yaml.MappingNode}
		_, _ = fmt.Fprintf(digest, "ConfigMap/%s\n", b.ConfigMap)
		for _, k := range b.Keys {
			v, ok := settings[k.Setting]
			if !ok {
				return nil, fmt.Errorf("boxsecrets: %s/%s reads the setting %s, which has no value", b.ConfigMap, k.Key, k.Setting)
			}
			pair(data, k.Key, v)
		}
		objs = append(objs, object{"ConfigMap", b.Namespace(), b.ConfigMapName(), "data", data})
	}
	rev := hex.EncodeToString(digest.Sum(nil))[:16]
	meta := func(name, ns string) map[string]any {
		m := map[string]any{"name": name, "annotations": map[string]string{RevisionAnnotation: rev},
			"labels": map[string]string{"app.kubernetes.io/managed-by": "sneakers-appliance"}}
		if ns != "" {
			m["namespace"] = ns
		}
		return m
	}
	var docs []any
	for _, ns := range nsOrder {
		docs = append(docs, map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": meta(ns, "")})
	}
	for _, o := range objs {
		d := map[string]any{"apiVersion": "v1", "kind": o.kind, "metadata": meta(o.name, o.ns), o.field: o.data}
		if o.kind == "Secret" {
			d["type"] = "Opaque"
		}
		docs = append(docs, d)
	}
	var out strings.Builder
	for i, d := range docs {
		b, err := yaml.Marshal(d)
		if err != nil {
			return nil, fmt.Errorf("boxsecrets: %w", err)
		}
		if i > 0 {
			out.WriteString("---\n")
		}
		out.Write(b)
	}
	return []byte(out.String()), nil
}

// StackRevision is the revision the stack file at p carries.
func StackRevision(p string) (string, error) {
	b, err := os.ReadFile(p) // #nosec G304 -- the box's own stack
	if err != nil {
		return "", fmt.Errorf("boxsecrets: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var o struct {
			Metadata struct {
				Annotations map[string]string `yaml:"annotations"`
			} `yaml:"metadata"`
		}
		if err := dec.Decode(&o); err != nil {
			break
		}
		if r := o.Metadata.Annotations[RevisionAnnotation]; r != "" {
			return r, nil
		}
	}
	return "", fmt.Errorf("boxsecrets: %s carries no revision", filepath.Base(p))
}

func value(b productspec.BoxSecret, k productspec.BoxKey, values, settings map[string]string) (string, error) {
	if k.Generate != "" {
		return values[b.Secret+"/"+k.Key], nil
	}
	if k.Setting != "" {
		v, ok := settings[k.Setting]
		if !ok {
			return "", fmt.Errorf("boxsecrets: %s/%s reads the setting %s, which has no value", b.Secret, k.Key, k.Setting)
		}
		return v, nil
	}
	parts, refs, err := b.Refs(k.Value)
	if err != nil {
		return "", err
	}
	var v strings.Builder
	for i, p := range parts {
		if !refs[i] {
			v.WriteString(p)
			continue
		}
		r, ok := values[p]
		if !ok {
			return "", fmt.Errorf("boxsecrets: %s/%s names %s, which has no value", b.Secret, k.Key, p)
		}
		v.WriteString(r)
	}
	return v.String(), nil
}

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func generate(kind string) (string, error) {
	switch kind {
	case productspec.GeneratePassword:
		b := make([]byte, 32)
		for i := range b {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alnum))))
			if err != nil {
				return "", fmt.Errorf("boxsecrets: %w", err)
			}
			b[i] = alnum[n.Int64()]
		}
		return string(b), nil
	case productspec.GenerateKey32, productspec.GenerateToken:
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("boxsecrets: %w", err)
		}
		if kind == productspec.GenerateToken {
			return base64.RawURLEncoding.EncodeToString(b), nil
		}
		return base64.StdEncoding.EncodeToString(b), nil
	}
	return "", fmt.Errorf("boxsecrets: no generator %q", kind)
}

// Known are the secret values the box holds: every value it made or was
// given for the product, and the settings that are passwords. The support
// bundle masks them wherever they turn up, so a value with nothing around
// it that says it's secret still doesn't get out.
func (s *Store) Known() ([]string, error) {
	values, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, v)
	}
	settings, err := s.settings()
	if err != nil {
		return out, err
	}
	for k, v := range settings {
		if strings.Contains(k, "password") && v != "" {
			out = append(out, v)
		}
	}
	return out, nil
}

func (s *Store) load() (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, ValuesFile)) // #nosec G304 -- the box's own settings file
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("boxsecrets: %w", err)
	}
	values := map[string]string{}
	if err := json.Unmarshal(b, &values); err != nil {
		return nil, fmt.Errorf("boxsecrets: %s doesn't parse: %w", ValuesFile, err)
	}
	return values, nil
}

func (s *Store) save(values map[string]string) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("boxsecrets: %w", err)
	}
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	b, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		return fmt.Errorf("boxsecrets: %w", err)
	}
	s.logger().Info("boxsecrets: values kept", log.F("keys", strings.Join(ids, " ")))
	return writeAtomic(filepath.Join(s.Dir, ValuesFile), append(b, '\n'))
}

// syncFile flushes f to the disk; tests watch the order.
var syncFile = func(f *os.File) error { return f.Sync() }

// writeAtomic replaces p with b so that a power cut leaves the old file or
// the new one, whole: the data is synced before the rename, and the directory
// after it. Without the first sync the rename can reach the disk ahead of the
// data, which leaves the box's only copy of its secrets empty.
func writeAtomic(p string, b []byte) error {
	tmp := p + ".new"
	defer func() { _ = os.Remove(tmp) }()
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the box's own settings and stack files
	if err != nil {
		return fmt.Errorf("boxsecrets: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("boxsecrets: %w", err)
	}
	if err := syncFile(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("boxsecrets: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("boxsecrets: %w", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("boxsecrets: %w", err)
	}
	d, err := os.Open(filepath.Dir(p)) // #nosec G304 -- the directory of the file just written
	if err != nil {
		return fmt.Errorf("boxsecrets: %w", err)
	}
	defer func() { _ = d.Close() }()
	if err := syncFile(d); err != nil {
		return fmt.Errorf("boxsecrets: %w", err)
	}
	return nil
}
