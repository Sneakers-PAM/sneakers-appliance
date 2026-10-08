// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// EnsureHostKeys makes the SSH host keys (ed25519 and RSA-3072) in dir
// when they are missing: accessd does this at start, so the console can
// show their fingerprints before sshd first runs.
func EnsureHostKeys(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, kind := range []string{"ed25519", "rsa"} {
		p := filepath.Join(dir, "ssh_host_"+kind+"_key")
		if _, err := os.Stat(p); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		var priv any
		if kind == "ed25519" {
			_, k, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			priv = k
		} else {
			k, err := rsa.GenerateKey(rand.Reader, 3072)
			if err != nil {
				return err
			}
			priv = k
		}
		block, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			return err
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return err
		}
		if err := os.WriteFile(p+".tmp", pem.EncodeToMemory(block), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(p+".pub", ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644); err != nil { // #nosec G306 -- a public key
			return err
		}
		if err := os.Rename(p+".tmp", p); err != nil {
			return fmt.Errorf("host key %s: %w", kind, err)
		}
	}
	return nil
}
