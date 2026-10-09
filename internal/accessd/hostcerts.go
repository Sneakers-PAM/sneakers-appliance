// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshconfig"
)

// HostCA signs the box's SSH host certificates (rootkey.Key).
type HostCA interface {
	HostCAPublicKey() ssh.PublicKey
	SignHostCert(pub ssh.PublicKey, principals []string, validAfter, validBefore time.Time) (*ssh.Certificate, error)
}

// Host certificates last a year and are renewed in their last 30 days.
const (
	hostCertLife  = 365 * 24 * time.Hour
	hostCertRenew = 30 * 24 * time.Hour
)

// SignHostCerts gives each host key in dir (ssh_host_<kind>_key.pub) a
// host certificate from ca for principals, the box's names and addresses,
// as <key>-cert.pub, which sshd presents (HostCertificate). A certificate
// is signed again when the key, the principals or the CA changed, or in
// its last 30 days; otherwise it's left alone. It reports whether any
// changed.
func SignHostCerts(ca HostCA, dir string, principals []string, now time.Time) (bool, error) {
	if len(principals) == 0 {
		return false, errors.New("host certificates: no name or address to sign them for")
	}
	changed := false
	for _, kind := range []string{"ed25519", "rsa"} {
		key := filepath.Join(dir, "ssh_host_"+kind+"_key")
		b, err := os.ReadFile(key + ".pub") // #nosec G304 -- the box's own host key
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return changed, fmt.Errorf("host certificate %s: %w", kind, err)
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			return changed, fmt.Errorf("host certificate %s: the host key doesn't parse: %w", kind, err)
		}
		if current(ca, key+sshconfig.CertSuffix, pub, principals, now) {
			continue
		}
		c, err := ca.SignHostCert(pub, principals, now.Add(-5*time.Minute), now.Add(hostCertLife))
		if err != nil {
			return changed, err
		}
		if err := writeAtomic(key+sshconfig.CertSuffix, ssh.MarshalAuthorizedKey(c)); err != nil {
			return changed, fmt.Errorf("host certificate %s: %w", kind, err)
		}
		changed = true
	}
	return changed, nil
}

// current reports whether the certificate at path is for pub and
// principals, from ca, and not in its last 30 days.
func current(ca HostCA, path string, pub ssh.PublicKey, principals []string, now time.Time) bool {
	b, err := os.ReadFile(path) // #nosec G304 -- the box's own host certificate
	if err != nil {
		return false
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return false
	}
	c, ok := pk.(*ssh.Certificate)
	return ok && c.CertType == ssh.HostCert && bytes.Equal(c.Key.Marshal(), pub.Marshal()) &&
		bytes.Equal(c.SignatureKey.Marshal(), ca.HostCAPublicKey().Marshal()) && slices.Equal(c.ValidPrincipals, principals) &&
		now.Add(hostCertRenew).Before(time.Unix(int64(min(c.ValidBefore, 1<<62)), 0)) // #nosec G115 -- clamped
}

func writeAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil { // #nosec G306 G703 -- a public certificate sshd reads, next to the box's own host key
		return err
	}
	return os.Rename(tmp, path)
}
