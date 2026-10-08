// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package certstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// The files :8443 serves from, in sneakers-osadmin's directory.
const (
	adminCert = "tls.crt"
	adminKey  = "tls.key"
	// AssignedMarker names the store certificate :8443 serves; while it's
	// there, sneakers-osadmin keeps the files as they are instead of making
	// a self-signed certificate for new names.
	AssignedMarker = "tls.assigned"
)

type adminFiles struct {
	crt, key []byte
	marker   string
}

// readNoFollow reads a file in osadmin's directory, which the osadmin user
// can write, so a link it planted isn't followed.
func readNoFollow(dir, name string) ([]byte, error) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDONLY|unix.O_NOFOLLOW, 0) // #nosec G304 -- osadmin's directory, links refused
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, maxPEM))
}

func readAdminFiles(dir string) (crt, key []byte, err error) {
	if crt, err = readNoFollow(dir, adminCert); err != nil {
		return nil, nil, fmt.Errorf("tls: %w", err)
	}
	if key, err = readNoFollow(dir, adminKey); err != nil {
		return nil, nil, fmt.Errorf("tls: %w", err)
	}
	return crt, key, nil
}

func readAdminLeaf(dir string) (*x509.Certificate, error) {
	crt, err := readNoFollow(dir, adminCert)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(crt)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s holds no certificate", adminCert)
	}
	return x509.ParseCertificate(blk.Bytes)
}

// AssignedID returns the store id in dir's marker, or "" when :8443
// serves the box's own self-signed certificate.
func AssignedID(dir string) string {
	b, err := readNoFollow(dir, AssignedMarker)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func backupAdmin(dir string) (adminFiles, error) {
	crt, key, err := readAdminFiles(dir)
	if err != nil {
		return adminFiles{}, err
	}
	return adminFiles{crt: crt, key: key, marker: AssignedID(dir)}, nil
}

// writeFile replaces dir/name atomically: a new file made in dir (never
// opening the old path, so a link there isn't followed), handed to own,
// synced, then renamed over the old one.
func writeFile(dir, name string, b []byte, own func(*os.File) error) error {
	f, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return fmt.Errorf("tls: write %s: %w", name, err)
	}
	tmp := f.Name()
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("tls: write %s: %w", name, err)
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(err)
	}
	if own != nil {
		if err := own(f); err != nil {
			return fail(err)
		}
	}
	if _, err := f.Write(b); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("tls: write %s: %w", name, err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("tls: write %s: %w", name, err)
	}
	return nil
}

// HandshakeProbe connects to port on every address until each serves the
// certificate with fingerprint, or ctx ends.
func HandshakeProbe(ctx context.Context, addrs []string, port, fingerprint string) error {
	if len(addrs) == 0 {
		return errors.New("no management address to check")
	}
	var last error
	for {
		last = nil
		for _, a := range addrs {
			got, err := servedFingerprint(ctx, net.JoinHostPort(a, port))
			if err != nil {
				last = err
				break
			}
			if got != fingerprint {
				last = fmt.Errorf("%s still serves %s", a, got)
				break
			}
		}
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return last
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func servedFingerprint(ctx context.Context, addr string) (string, error) {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{
		// Only the served certificate's fingerprint is compared; nothing
		// is sent over the connection.
		InsecureSkipVerify: true, // #nosec G402 -- the fingerprint is the check
		MinVersion:         tls.VersionTLS12,
	}}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	tc, ok := c.(*tls.Conn)
	if !ok {
		return "", errors.New("not a TLS connection")
	}
	peers := tc.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return "", errors.New("no certificate served")
	}
	return Fingerprint(peers[0].Raw), nil
}
