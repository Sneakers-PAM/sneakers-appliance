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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	log "github.com/Bugs5382/go-log"
	"gopkg.in/yaml.v3"

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
	Logger    log.Logger
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
	if len(spec.BoxSecrets) == 0 {
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
	made := 0
	for _, b := range spec.BoxSecrets {
		for _, k := range b.Keys {
			id := b.Secret + "/" + k.Key
			if k.Generate == "" || values[id] != "" {
				continue
			}
			v, err := generate(k.Generate)
			if err != nil {
				return err
			}
			values[id] = v
			made++
		}
	}
	if made > 0 {
		if err := s.save(values); err != nil {
			return err
		}
	}
	doc, err := Render(spec, values)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stack, 0o700); err != nil {
		return fmt.Errorf("boxsecrets: %w", err)
	}
	if err := writeAtomic(filepath.Join(stack, productspec.BoxSecretsStack+".yaml"), doc); err != nil {
		return err
	}
	s.logger().Info("boxsecrets: the box secrets are in place", log.F("secrets", len(spec.BoxSecrets)), log.F("generated", made))
	return nil
}

// Render is the stack for spec's box secrets with values: each namespace
// they live in, then each Secret with its keys in order.
func Render(spec productspec.Spec, values map[string]string) ([]byte, error) {
	var docs []any
	nss := map[string]bool{}
	for _, b := range spec.BoxSecrets {
		if !nss[b.Namespace()] {
			nss[b.Namespace()] = true
			docs = append(docs, map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": b.Namespace()}})
		}
	}
	for _, b := range spec.BoxSecrets {
		data := yaml.Node{Kind: yaml.MappingNode}
		for _, k := range b.Keys {
			v, err := value(b, k, values)
			if err != nil {
				return nil, err
			}
			data.Content = append(data.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Value: k.Key},
				&yaml.Node{Kind: yaml.ScalarNode, Value: v, Style: yaml.DoubleQuotedStyle})
		}
		docs = append(docs, map[string]any{
			"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
			"metadata": map[string]any{"name": b.SecretName(), "namespace": b.Namespace(),
				"labels": map[string]string{"app.kubernetes.io/managed-by": "sneakers-appliance"}},
			"stringData": &data,
		})
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

func value(b productspec.BoxSecret, k productspec.BoxKey, values map[string]string) (string, error) {
	if k.Generate != "" {
		return values[b.Secret+"/"+k.Key], nil
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

func writeAtomic(p string, b []byte) error {
	tmp := p + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("boxsecrets: %w", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("boxsecrets: %w", err)
	}
	return nil
}
