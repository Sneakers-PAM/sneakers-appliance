// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package productsetup keeps the product's one-time setup token: the value
// the product's first-run setup (/admin/setup) asks for before it creates
// the product's first admin. The box makes it once, after its own first
// admin exists; :8443 and the closed shell's "sneakers setup-token" read
// it from here, and the product's start puts it in the product's Secret.
// Once the product reports its first admin exists, the token is removed
// for good and a marker says so.
package productsetup

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// TokenFile holds the token while it's unused.
	TokenFile = "token"
	// ConsumedFile marks that the product's first admin exists.
	ConsumedFile = "consumed"
	// Prefix starts every token.
	Prefix = "stp_"
)

// Store is the token's directory, /var/lib/sneakers/osadmin-api/product-setup
// on the box (root only).
type Store struct{ dir string }

// New returns the store in dir.
func New(dir string) *Store { return &Store{dir: dir} }

// Dir is the store's directory.
func (s *Store) Dir() string { return s.dir }

// Ensure makes the token when there's none and it was never consumed.
func (s *Store) Ensure() error {
	if s.Consumed() {
		return nil
	}
	if _, ok := s.Token(); ok {
		return nil
	}
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("product setup token: %w", err)
	}
	tok := Prefix + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("product setup token: %w", err)
	}
	return write(filepath.Join(s.dir, TokenFile), []byte(tok+"\n"))
}

// Token is the unused token, if there is one.
func (s *Store) Token() (string, bool) {
	b, err := os.ReadFile(filepath.Join(s.dir, TokenFile)) // #nosec G304 -- the store's own file
	if err != nil {
		return "", false
	}
	t := strings.TrimSpace(string(b))
	return t, strings.HasPrefix(t, Prefix)
}

// Consumed reports whether the product's first admin exists.
func (s *Store) Consumed() bool {
	_, err := os.Stat(filepath.Join(s.dir, ConsumedFile))
	return err == nil
}

// Consume marks the token used and removes it.
func (s *Store) Consume() error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("product setup token: %w", err)
	}
	if err := write(filepath.Join(s.dir, ConsumedFile), nil); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(s.dir, TokenFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("product setup token: %w", err)
	}
	return nil
}

func write(p string, b []byte) error {
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the store's own file
	if err != nil {
		return fmt.Errorf("product setup token: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("product setup token: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("product setup token: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("product setup token: %w", err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("product setup token: %w", err)
	}
	return nil
}
