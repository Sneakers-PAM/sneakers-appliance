// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package elevation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	log "github.com/Bugs5382/go-log"
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

// SealedName is the KeyCustody item the user CA is sealed as.
const SealedName = "ssh-user-ca"

// Sealer keeps the user CA's private key: init's KeyCustody on the box, so
// in TPM mode a copied state volume doesn't yield it even with the state
// key.
type Sealer interface {
	Seal(name string, secret []byte) error
	// Unseal returns the item; ok is false when it was never sealed.
	Unseal(name string) (secret []byte, ok bool, err error)
}

// loadCA unseals the user CA, or makes and seals one the first time. A CA
// kept as a plain key file in dir (how accessd kept it before KeyCustody
// was served) is sealed as it is, so certificates keep working, and the
// file is removed only once the sealed copy reads back.
func loadCA(dir string, sealer Sealer, lg log.Logger) (ssh.Signer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("user CA: %w", err)
	}
	p := filepath.Join(dir, UserCAFile)
	b, ok, err := sealer.Unseal(SealedName)
	if err != nil {
		return nil, fmt.Errorf("user CA: unseal: %w", err)
	}
	if !ok {
		b, err = os.ReadFile(p) // #nosec G304 -- the interim CA file in the state directory
		switch {
		case err == nil:
			lg.Info("elevation: moving the user CA file into its sealed item")
		case errors.Is(err, fs.ErrNotExist):
			if b, err = newCA(); err != nil {
				return nil, err
			}
			lg.Info("elevation: made a user CA")
		default:
			return nil, fmt.Errorf("user CA: %w", err)
		}
		if _, err := ssh.ParsePrivateKey(b); err != nil {
			return nil, fmt.Errorf("user CA: %s doesn't parse: %w", p, err)
		}
		if err := sealer.Seal(SealedName, b); err != nil {
			return nil, fmt.Errorf("user CA: seal: %w", err)
		}
		back, ok, err := sealer.Unseal(SealedName)
		if err != nil || !ok || !bytes.Equal(back, b) {
			return nil, fmt.Errorf("user CA: the sealed copy doesn't read back (%v)", err)
		}
	}
	s, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("user CA: the sealed item doesn't parse: %w", err)
	}
	if err := removeInterim(p); err != nil {
		return nil, err
	}
	return s, writePub(p, s.PublicKey())
}

func newCA() ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("user CA: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "sneakers-appliance user CA")
	if err != nil {
		return nil, fmt.Errorf("user CA: %w", err)
	}
	return pem.EncodeToMemory(block), nil
}

// removeInterim overwrites the interim key file before removing it, so its
// blocks don't keep the key on the state volume.
func removeInterim(p string) error {
	fi, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("user CA: %w", err)
	}
	if err := writeFile(p, make([]byte, fi.Size()), 0o600); err != nil {
		return fmt.Errorf("user CA: %w", err)
	}
	if err := os.Remove(p); err != nil {
		return fmt.Errorf("user CA: %w", err)
	}
	return nil
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
