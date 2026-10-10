// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"
	"golang.org/x/sys/unix"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/certstore"
)

// The certificate files in Paths.OwnDir.
const (
	certFile = "tls.crt"
	keyFile  = "tls.key"
)

// CertInfo describes :8443's certificate for Status.
type CertInfo struct {
	Fingerprint string
	Expires     time.Time
	// SelfSigned is the box's own certificate: no store certificate is
	// assigned to :8443.
	SelfSigned bool
}

// EnsureCert loads :8443's certificate from dir. While a store certificate
// is assigned (certstore.AssignedMarker) it is served as it is. Otherwise
// the box's own self-signed ECDSA P-256 one is kept, or made new when
// there is none, it expires within 30 days, it names another host, or it
// doesn't name one of addrs. A certificate that names more addresses than
// addrs is kept: after a boot the addresses come back one at a time, and
// the fingerprint an admin checked on the console must not change with
// each. The key never leaves dir.
func EnsureCert(dir, hostname string, addrs []string, now time.Time) (tls.Certificate, CertInfo, error) {
	if certstore.AssignedID(dir) != "" {
		if c, info, err := loadCert(dir); err == nil {
			return c, info, nil
		}
		// An assigned certificate that doesn't load falls back to a new
		// self-signed one, and the marker goes so the store sees it.
		if err := os.Remove(filepath.Join(dir, certstore.AssignedMarker)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return tls.Certificate{}, CertInfo{}, fmt.Errorf("tls: %w", err)
		}
	}
	if c, info, err := loadCert(dir); err == nil {
		leaf := c.Leaf
		if covers(leaf, hostname, addrs) && now.Add(certstore.RenewBefore).Before(leaf.NotAfter) {
			return c, info, nil
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, CertInfo{}, fmt.Errorf("tls: %w", err)
	}
	crt, key, err := certstore.NewSelfSigned(hostname, addrs, now)
	if err != nil {
		return tls.Certificate{}, CertInfo{}, err
	}
	if err := writeAtomic(filepath.Join(dir, keyFile), key); err != nil {
		return tls.Certificate{}, CertInfo{}, err
	}
	if err := writeAtomic(filepath.Join(dir, certFile), crt); err != nil {
		return tls.Certificate{}, CertInfo{}, err
	}
	return loadCert(dir)
}

func loadCert(dir string) (tls.Certificate, CertInfo, error) {
	c, err := tls.LoadX509KeyPair(filepath.Join(dir, certFile), filepath.Join(dir, keyFile))
	if err != nil {
		return tls.Certificate{}, CertInfo{}, fmt.Errorf("tls: %w", err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return tls.Certificate{}, CertInfo{}, fmt.Errorf("tls: %w", err)
	}
	c.Leaf = leaf
	return c, CertInfo{Fingerprint: Fingerprint(leaf.Raw), Expires: leaf.NotAfter, SelfSigned: certstore.AssignedID(dir) == ""}, nil
}

// ReadCertInfo describes the certificate in dir without reading its key.
// The directory is sneakers-osadmin's, so a link there isn't followed.
func ReadCertInfo(dir string) (CertInfo, error) {
	f, err := os.OpenFile(filepath.Join(dir, certFile), os.O_RDONLY|unix.O_NOFOLLOW, 0) // #nosec G304 -- the certificate under osadmin's own directory, links refused
	if err != nil {
		return CertInfo{}, fmt.Errorf("tls: %w", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return CertInfo{}, fmt.Errorf("tls: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return CertInfo{}, fmt.Errorf("tls: %s holds no certificate", certFile)
	}
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return CertInfo{}, fmt.Errorf("tls: %w", err)
	}
	return CertInfo{Fingerprint: Fingerprint(leaf.Raw), Expires: leaf.NotAfter, SelfSigned: certstore.AssignedID(dir) == ""}, nil
}

// Fingerprint is a certificate's SHA-256 as colon-separated hex, the form
// the console shows for checking on first visit.
func Fingerprint(der []byte) string { return certstore.Fingerprint(der) }

// CertSource serves :8443's certificate and re-reads it when accessd
// swaps the files, so a new certificate needs no restart. A pair that
// doesn't load (the key written, the certificate not yet) keeps the last
// good one until the next handshake.
type CertSource struct {
	dir    string
	logger log.Logger
	mu     sync.Mutex
	cur    *tls.Certificate
	stamp  string
}

// NewCertSource starts from c, the certificate EnsureCert loaded from dir.
func NewCertSource(dir string, c tls.Certificate, lg log.Logger) *CertSource {
	if lg == nil {
		lg = log.Nop()
	}
	src := &CertSource{dir: dir, logger: lg, cur: &c}
	src.stamp = src.stat()
	return src
}

// GetCertificate is the tls.Config callback.
func (c *CertSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if st := c.stat(); st != c.stamp {
		next, info, err := loadCert(c.dir)
		if err != nil {
			c.logger.Warn("osadmin: the new :8443 certificate doesn't load yet; serving the previous one", log.F("error", err.Error()))
			return c.cur, nil
		}
		c.cur, c.stamp = &next, st
		c.logger.Info("osadmin: :8443 certificate reloaded", log.F("fingerprint", info.Fingerprint), log.F("expires", info.Expires), log.F("selfSigned", info.SelfSigned))
	}
	return c.cur, nil
}

// stat identifies the current files: a swap renames new files in, so the
// inode changes.
func (c *CertSource) stat() string {
	var b strings.Builder
	for _, name := range []string{certFile, keyFile} {
		fi, err := os.Lstat(filepath.Join(c.dir, name))
		if err != nil {
			b.WriteString("-;")
			continue
		}
		ino := uint64(0)
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			ino = st.Ino
		}
		fmt.Fprintf(&b, "%d:%d:%d;", ino, fi.Size(), fi.ModTime().UnixNano())
	}
	return b.String()
}

// covers reports whether leaf names hostname as its host and every one of
// addrs.
func covers(leaf *x509.Certificate, hostname string, addrs []string) bool {
	if firstOr(leaf.DNSNames) != hostname {
		return false
	}
	have := ipStrings(leaf.IPAddresses)
	for _, a := range sanList(hostname, addrs)[1:] {
		if !slices.Contains(have, a) {
			return false
		}
	}
	return true
}

func sanList(hostname string, addrs []string) []string {
	out := []string{hostname}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			out = append(out, ip.String())
		}
	}
	slices.Sort(out[1:])
	return out
}

func firstOr(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func ipStrings(ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
