// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package elevation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// The files in the SSH state directory (/var/lib/sneakers/ssh).
const (
	// UserCAFile is the user CA's private key; UserCAFile+".pub" is the
	// public key sshd trusts for maint.
	UserCAFile = "user_ca"
	// RevokedFile is the revocation list sshd reads (RevokedKeys).
	RevokedFile = "revoked.krl"
	// SerialFile holds the last certificate serial issued.
	SerialFile = "serial"
)

// SealedName is the KeyCustody item the user CA is meant to be sealed as.
const SealedName = "ssh-user-ca"

// loadCA reads the user CA from dir, or makes one the first time.
//
// INTERIM: the private key is kept as a plain OpenSSH key file, mode 0600,
// root's, on the encrypted state volume. The design seals it through
// init's KeyCustody.Seal(SealedName), so a copied state volume doesn't
// yield it in TPM mode; init doesn't serve KeyCustody yet. When it does,
// this function moves the key into the sealed item and removes the file.
func loadCA(dir string) (ssh.Signer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("user CA: %w", err)
	}
	p := filepath.Join(dir, UserCAFile)
	b, err := os.ReadFile(p) // #nosec G304 -- the CA file in the state directory
	if err == nil {
		if err := os.Chmod(p, 0o600); err != nil {
			return nil, fmt.Errorf("user CA: %w", err)
		}
		s, err := ssh.ParsePrivateKey(b)
		if err != nil {
			return nil, fmt.Errorf("user CA: %s doesn't parse: %w", p, err)
		}
		return s, writePub(p, s.PublicKey())
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("user CA: %w", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("user CA: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "sneakers-appliance user CA")
	if err != nil {
		return nil, fmt.Errorf("user CA: %w", err)
	}
	if err := writeFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("user CA: %w", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("user CA: %w", err)
	}
	return s, writePub(p, s.PublicKey())
}

func writePub(priv string, pub ssh.PublicKey) error {
	if err := writeFile(priv+".pub", ssh.MarshalAuthorizedKey(pub), 0o644); err != nil {
		return fmt.Errorf("user CA: %w", err)
	}
	return nil
}

// writeFile replaces path atomically with data, synced.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode) // #nosec G304 -- a file in a directory accessd owns
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
