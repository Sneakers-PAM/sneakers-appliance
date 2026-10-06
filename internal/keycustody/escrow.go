// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
)

// SealedDir is where sealed items live on the state volume.
const SealedDir = "/var/lib/sneakers/sealed"

var itemNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// itemKey derives the sealed items' key from the state key, so the items
// are exactly as safe as the state (the TPM or the key file holds it) and
// need no second protector.
func itemKey(stateKey []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, stateKey, nil, "sneakers sealed items v1", 32)
}

func (c *Custody) sealedDir() string {
	if c.d.SealedDir != "" {
		return c.d.SealedDir
	}
	return SealedDir
}

func (c *Custody) aead() (cipher.AEAD, error) {
	if c.key == nil {
		return nil, codes.New(codes.KeyCustodyLocked, "the state isn't unlocked")
	}
	k, err := itemKey(c.key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal stores a small secret (the vault root key first) under the state
// key's protector: AES-256-GCM with a key derived from the state key, the
// item's name as associated data, written atomically.
func (c *Custody) Seal(name string, secret []byte) error {
	if !itemNameRE.MatchString(name) {
		return codes.New(codes.KeyCustodyInvalid, "sealed item name %q", name)
	}
	a, err := c.aead()
	if err != nil {
		return err
	}
	nonce := make([]byte, a.NonceSize())
	if err := c.d.Rand(nonce); err != nil {
		return err
	}
	blob := a.Seal(nonce, nonce, secret, []byte(name))
	dir := c.sealedDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+name+".new")
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}

// Unseal returns a sealed secret.
func (c *Custody) Unseal(name string) ([]byte, error) {
	if !itemNameRE.MatchString(name) {
		return nil, codes.New(codes.KeyCustodyInvalid, "sealed item name %q", name)
	}
	a, err := c.aead()
	if err != nil {
		return nil, err
	}
	blob, err := os.ReadFile(filepath.Join(c.sealedDir(), name)) // #nosec G304 -- a validated item name under the sealed directory
	if errors.Is(err, os.ErrNotExist) {
		return nil, codes.New(codes.KeyCustodyNotFound, "no sealed item %s", name)
	}
	if err != nil {
		return nil, err
	}
	if len(blob) < a.NonceSize() {
		return nil, codes.New(codes.KeyCustodyLocked, "sealed item %s is damaged", name)
	}
	out, err := a.Open(nil, blob[:a.NonceSize()], blob[a.NonceSize():], []byte(name))
	if err != nil {
		return nil, codes.New(codes.KeyCustodyLocked, "sealed item %s doesn't open with this box's state key", name)
	}
	return out, nil
}

// EscrowContents is what an escrow bundle holds once decrypted.
type EscrowContents struct {
	Version  int               `json:"version"`
	StateKey []byte            `json:"stateKey"`
	Items    map[string][]byte `json:"items"`
}

// Escrow returns the escrow bundle: the state key and every sealed item,
// encrypted with age to one to three SSH recovery keys (ssh-ed25519 or
// ssh-rsa; security-key types are refused, since a restore must not need
// the hardware the key was made on).
func (c *Custody) Escrow(recipients []string) ([]byte, error) {
	if len(recipients) < 1 || len(recipients) > 3 {
		return nil, codes.New(codes.KeyCustodyRecipients, "the escrow takes one to three recovery keys, not %d", len(recipients))
	}
	var rs []age.Recipient
	for _, r := range recipients {
		r = strings.TrimSpace(r)
		if !strings.HasPrefix(r, "ssh-ed25519 ") && !strings.HasPrefix(r, "ssh-rsa ") {
			return nil, codes.New(codes.KeyCustodyRecipients, "a recovery key must be ssh-ed25519 or ssh-rsa")
		}
		rec, err := agessh.ParseRecipient(r)
		if err != nil {
			return nil, codes.New(codes.KeyCustodyRecipients, "a recovery key doesn't parse: %v", err)
		}
		rs = append(rs, rec)
	}
	if c.key == nil {
		return nil, codes.New(codes.KeyCustodyLocked, "the state isn't unlocked")
	}
	items := map[string][]byte{}
	names, err := c.sealedNames()
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		v, err := c.Unseal(n)
		if err != nil {
			return nil, err
		}
		items[n] = v
	}
	plain, err := json.Marshal(EscrowContents{Version: 1, StateKey: c.key, Items: items})
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, rs...)
	if err != nil {
		return nil, fmt.Errorf("keycustody: escrow: %w", err)
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
