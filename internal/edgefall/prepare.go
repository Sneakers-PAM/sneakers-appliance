// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package edgefall

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// The box's certificate files, in osadmin's directory and in edgefall's.
const (
	certFile = "tls.crt"
	keyFile  = "tls.key"
)

// maxPEM bounds a copied file.
const maxPEM = 64 << 10

// Prepare copies the box's :8443 certificate and key from src (osadmin's
// directory, which the osadmin user can write, so links are never
// followed) into dst, edgefall's own directory, owned by uid and gid with
// mode 0700 and the files 0600. It runs as root before every start, as
// k0s-interim hands the same pair to Traefik as box-tls. Without a whole
// pair it leaves none behind.
func Prepare(src, dst string, uid, gid int) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dst, 0o700); err != nil {
		return err
	}
	if err := os.Lchown(dst, uid, gid); err != nil {
		return err
	}
	crt, cerr := readNoFollow(filepath.Join(src, certFile))
	key, kerr := readNoFollow(filepath.Join(src, keyFile))
	if err := errors.Join(cerr, kerr); err != nil {
		for _, name := range []string{certFile, keyFile} {
			if rerr := os.Remove(filepath.Join(dst, name)); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				return rerr
			}
		}
		return nil
	}
	for name, b := range map[string][]byte{certFile: crt, keyFile: key} {
		if err := writeOwned(filepath.Join(dst, name), b, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func readNoFollow(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW, 0) // #nosec G304 -- osadmin's directory, links refused
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s isn't a file", p)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxPEM+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxPEM {
		return nil, fmt.Errorf("%s is over %d bytes", p, maxPEM)
	}
	return b, nil
}

func writeOwned(p string, b []byte, uid, gid int) error {
	tmp := p + ".tmp"
	_ = os.Remove(tmp)
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Lchown(tmp, uid, gid); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// LoadCert reads the pair Prepare left in dir, at every claim.
func LoadCert(dir string) func() (tls.Certificate, error) {
	return func() (tls.Certificate, error) {
		crt, cerr := readNoFollow(filepath.Join(dir, certFile))
		key, kerr := readNoFollow(filepath.Join(dir, keyFile))
		if err := errors.Join(cerr, kerr); err != nil {
			return tls.Certificate{}, err
		}
		return tls.X509KeyPair(crt, key)
	}
}
