// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package productedge is the certificate the box gives the product's edge
// (Traefik on 443): the box-tls Secret in the sneakers-edge namespace, which
// k0s applies from its own stack. The Secret carries the chain and key and
// a Traefik dynamic config with them inline, which the edge mounts with its
// routes in one directory, so Traefik reloads a new certificate as soon as
// the kubelet updates the volume, with no restart. A certificate the
// Certificates page assigns to the Product (443) endpoint is kept on the
// state volume and wins over the box's own (the :8443 one), which
// k0s-interim hands in at every k0s start otherwise.
package productedge

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Stack is the k0s stack the Secret goes in.
const Stack = "box-tls"

// DynamicKey is the Secret's Traefik dynamic config, mounted as tls.yaml
// next to the edge's routes.
const DynamicKey = "traefik-tls.yaml"

// The files an assigned certificate is kept in, in Dir.
const (
	certFile = "product.crt"
	keyFile  = "product.key"
)

// Edge is the product's edge on the box.
type Edge struct {
	// Slot is the product's current slot; it has bundle.json once a
	// product is installed.
	Slot string
	// Dir keeps the assigned certificate (/var/lib/sneakers/platform/tls).
	Dir string
	// AdminDir holds the box's own certificate, :8443's tls.crt and
	// tls.key (/var/lib/sneakers/osadmin).
	AdminDir string
	// Manifests is k0s's manifests directory (/var/lib/k0s/manifests).
	Manifests string
}

// Installed reports whether a product is installed.
func (e *Edge) Installed() bool {
	_, err := os.Stat(filepath.Join(e.Slot, "bundle.json"))
	return err == nil
}

// Current is the assigned certificate, else the box's own.
func (e *Edge) Current() ([]byte, []byte, error) {
	crt, key, err := readPair(e.Dir, certFile, keyFile)
	if err == nil {
		return crt, key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, err
	}
	return readPair(e.AdminDir, "tls.crt", "tls.key")
}

func readPair(dir, c, k string) ([]byte, []byte, error) {
	crt, err := os.ReadFile(filepath.Join(dir, c)) // #nosec G304 -- the box's own certificate files
	if err != nil {
		return nil, nil, err
	}
	key, err := os.ReadFile(filepath.Join(dir, k)) // #nosec G304 -- as above
	if err != nil {
		return nil, nil, err
	}
	return crt, key, nil
}

// Set keeps crt and key for the edge and writes the box-tls stack, which
// k0s applies; the edge reloads it live.
func (e *Edge) Set(crt, key []byte) error {
	if err := os.MkdirAll(e.Dir, 0o700); err != nil {
		return fmt.Errorf("productedge: %w", err)
	}
	if err := writeAtomic(filepath.Join(e.Dir, keyFile), key); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(e.Dir, certFile), crt); err != nil {
		return err
	}
	return e.writeStack(crt, key)
}

// Reset drops the assigned certificate and writes the box-tls stack with
// the box's own (the :8443 one) again.
func (e *Edge) Reset() error {
	for _, n := range []string{certFile, keyFile} {
		if err := os.Remove(filepath.Join(e.Dir, n)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("productedge: %w", err)
		}
	}
	crt, key, err := readPair(e.AdminDir, "tls.crt", "tls.key")
	if err != nil {
		return fmt.Errorf("productedge: the box's own certificate: %w", err)
	}
	return e.writeStack(crt, key)
}

func (e *Edge) writeStack(crt, key []byte) error {
	b, err := Render(crt, key)
	if err != nil {
		return err
	}
	dir := filepath.Join(e.Manifests, Stack)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("productedge: %w", err)
	}
	return writeAtomic(filepath.Join(dir, Stack+".yaml"), b)
}

// Render is the box-tls stack for crt and key: the sneakers-edge namespace
// and the Secret, with the Traefik dynamic config that makes them the
// default certificate.
func Render(crt, key []byte) ([]byte, error) {
	type certificate struct {
		CertFile string `yaml:"certFile"`
		KeyFile  string `yaml:"keyFile"`
	}
	dyn := map[string]any{"tls": map[string]any{"stores": map[string]any{"default": map[string]any{
		"defaultCertificate": certificate{CertFile: string(crt), KeyFile: string(key)},
	}}}}
	d, err := yaml.Marshal(dyn)
	if err != nil {
		return nil, fmt.Errorf("productedge: %w", err)
	}
	ns, err := yaml.Marshal(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "sneakers-edge"}})
	if err != nil {
		return nil, fmt.Errorf("productedge: %w", err)
	}
	sec, err := yaml.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/tls",
		"metadata":   map[string]any{"name": "box-tls", "namespace": "sneakers-edge"},
		"stringData": map[string]string{"tls.crt": string(crt), "tls.key": string(key), DynamicKey: string(d)},
	})
	if err != nil {
		return nil, fmt.Errorf("productedge: %w", err)
	}
	return append(append(ns, []byte("---\n")...), sec...), nil
}

func writeAtomic(p string, b []byte) error {
	tmp := p + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("productedge: %w", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("productedge: %w", err)
	}
	return nil
}
