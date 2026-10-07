// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// The certificate files in Paths.OwnDir.
const (
	certFile = "tls.crt"
	keyFile  = "tls.key"
	// certLifetime and certRenewBefore keep the self-signed certificate
	// inside the lifetime browsers accept.
	certLifetime    = 397 * 24 * time.Hour
	certRenewBefore = 30 * 24 * time.Hour
)

// CertInfo describes :8443's certificate for Status.
type CertInfo struct {
	Fingerprint string
	Expires     time.Time
	SelfSigned  bool
}

// EnsureCert loads :8443's own certificate from dir, or makes a new
// self-signed ECDSA P-256 one when there is none, it expires within 30
// days, or its names aren't hostname and addrs. The key never leaves dir.
func EnsureCert(dir, hostname string, addrs []string, now time.Time) (tls.Certificate, CertInfo, error) {
	want := sanList(hostname, addrs)
	if c, info, err := loadCert(dir); err == nil {
		leaf := c.Leaf
		if slices.Equal(sanList(firstOr(leaf.DNSNames), ipStrings(leaf.IPAddresses)), want) && now.Add(certRenewBefore).Before(leaf.NotAfter) {
			return c, info, nil
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, CertInfo{}, fmt.Errorf("tls: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, CertInfo{}, fmt.Errorf("tls: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, CertInfo{}, fmt.Errorf("tls: %w", err)
	}
	cn := hostname
	if cn == "" && len(addrs) > 0 {
		cn = addrs[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Sneakers-PAM appliance admin"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(certLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if hostname != "" {
		tmpl.DNSNames = []string{hostname}
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, CertInfo{}, fmt.Errorf("tls: %w", err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, CertInfo{}, fmt.Errorf("tls: %w", err)
	}
	if err := writeAtomic(filepath.Join(dir, keyFile), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})); err != nil {
		return tls.Certificate{}, CertInfo{}, err
	}
	if err := writeAtomic(filepath.Join(dir, certFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
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
	return c, CertInfo{Fingerprint: Fingerprint(leaf.Raw), Expires: leaf.NotAfter, SelfSigned: leaf.Subject.String() == leaf.Issuer.String()}, nil
}

// ReadCertInfo describes the certificate in dir without reading its key.
// The directory is sneakers-osadmin's, so a link there isn't followed.
func ReadCertInfo(dir string) (CertInfo, error) {
	f, err := os.OpenFile(filepath.Join(dir, certFile), os.O_RDONLY|unix.O_NOFOLLOW, 0)
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
	return CertInfo{Fingerprint: Fingerprint(leaf.Raw), Expires: leaf.NotAfter, SelfSigned: leaf.Subject.String() == leaf.Issuer.String()}, nil
}

// Fingerprint is a certificate's SHA-256 as colon-separated hex, the form
// the console shows for checking on first visit.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
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
