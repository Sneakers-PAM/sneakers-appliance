// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package boxsettings keeps the settings an admin sets for the product on
// :8443, such as its mail relay, on the state volume, and gives them to the
// product by the setting names its product.yaml reads
// (productspec.IsSetting): the non-secret ones as box settings ConfigMaps,
// the password and anything built from it as box secrets (package
// boxsecrets). An unset setting has a default, so no stack is ever left
// with a placeholder.
package boxsettings

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

// File keeps the settings in Store.Dir (mode 0600: it holds the relay
// password).
const File = "box-settings.json"

// The relay connection's TLS modes.
const (
	// TLSNone sends mail, and the relay password, unencrypted.
	TLSNone = "none"
	// TLSStartTLS upgrades the connection with STARTTLS before anything
	// else, and refuses a relay that doesn't offer it.
	TLSStartTLS = "starttls"
	// TLSImplicit speaks TLS from the first byte (usually port 465).
	TLSImplicit = "tls"
)

// DefaultPort is the submission port.
const DefaultPort = 587

// maxCA bounds the relay CA's PEM.
const maxCA = 64 << 10

// Email is the product's mail relay. No Host means no relay: the product
// sends no mail.
type Email struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	From     string `json:"from"`
	Username string `json:"username"`
	Password string `json:"password"`
	TLS      string `json:"tls"`
	// Verify checks the relay's certificate (starttls and tls).
	Verify bool `json:"verify"`
	// CA is the relay's CA, PEM, trusted on top of the system roots.
	CA string `json:"ca"`
}

// DefaultEmail is no relay, with the submission port and STARTTLS.
func DefaultEmail() Email { return Email{Port: DefaultPort, TLS: TLSStartTLS, Verify: true} }

// Configured reports whether a relay is set.
func (e Email) Configured() bool { return e.Host != "" }

// Encrypted reports whether mail goes to the relay encrypted and verified;
// otherwise mail and the relay password are sent unencrypted, or to a
// relay that isn't checked.
func (e Email) Encrypted() bool { return e.TLS != TLSNone && e.Verify }

var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$`)

func refused(format string, args ...any) error {
	return codes.New(codes.EmailInvalid, format, args...)
}

// Check refuses settings no mail could go out with. With no host, nothing
// else is looked at.
func (e Email) Check() error {
	if e.Host == "" {
		return nil
	}
	if len(e.Host) > 253 || (!hostRE.MatchString(e.Host) && net.ParseIP(e.Host) == nil) {
		return refused("the relay host %q isn't a host name or an address", e.Host)
	}
	if e.Port < 1 || e.Port > 65535 {
		return refused("the relay port %d isn't 1 to 65535", e.Port)
	}
	if a, err := mail.ParseAddress(e.From); err != nil || a.Name != "" || a.Address != e.From {
		return refused("the from address %q isn't a plain email address", e.From)
	}
	switch e.TLS {
	case TLSNone, TLSStartTLS, TLSImplicit:
	default:
		return refused("the TLS mode %q isn't %s, %s or %s", e.TLS, TLSNone, TLSStartTLS, TLSImplicit)
	}
	if e.CA != "" {
		if _, err := e.pool(); err != nil {
			return err
		}
	}
	if strings.ContainsAny(e.Username, "\r\n\x00") || len(e.Username) > 256 {
		return refused("the relay username has a line break or is too long")
	}
	if strings.ContainsAny(e.Password, "\r\n\x00") || len(e.Password) > 1024 {
		return refused("the relay password has a line break or is too long")
	}
	if e.Password != "" && e.Username == "" {
		return refused("a relay password needs its username")
	}
	return nil
}

// pool is the system roots and the relay's CA.
func (e Email) pool() (*x509.CertPool, error) {
	if len(e.CA) > maxCA {
		return nil, refused("the relay CA is over %d KiB", maxCA>>10)
	}
	rest := []byte(e.CA)
	var certs []*x509.Certificate
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, refused("the relay CA has a certificate that doesn't parse: %v", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, refused("the relay CA holds no PEM certificate")
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}

// URI is the relay as one URI, in the form Ory's courier reads:
// smtps:// for implicit TLS, else smtp://; disable_starttls=true for no
// TLS; skip_ssl_verify=true when the certificate isn't verified. With no
// relay it names localhost:25, where nothing listens.
func (e Email) URI() string {
	if !e.Configured() {
		return "smtp://localhost:25/?disable_starttls=true"
	}
	u := url.URL{Scheme: "smtp", Host: net.JoinHostPort(e.Host, strconv.Itoa(e.Port)), Path: "/"}
	if e.TLS == TLSImplicit {
		u.Scheme = "smtps"
	}
	if e.Username != "" {
		u.User = url.UserPassword(e.Username, e.Password)
	}
	q := url.Values{}
	if e.TLS == TLSNone {
		q.Set("disable_starttls", "true")
	}
	if !e.Verify {
		q.Set("skip_ssl_verify", "true")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Values are the settings by the names a product.yaml reads.
func (e Email) Values() map[string]string {
	return map[string]string{
		productspec.SettingEmailHost:       e.Host,
		productspec.SettingEmailPort:       strconv.Itoa(e.Port),
		productspec.SettingEmailFrom:       e.From,
		productspec.SettingEmailUsername:   e.Username,
		productspec.SettingEmailTLS:        e.TLS,
		productspec.SettingEmailSkipVerify: strconv.FormatBool(!e.Verify),
		productspec.SettingEmailCA:         e.CA,
		productspec.SettingEmailPassword:   e.Password,
		productspec.SettingEmailURI:        e.URI(),
	}
}

// Store is the box's settings on the state volume.
type Store struct {
	// Dir is the platform settings directory (/var/lib/sneakers/platform).
	Dir string
}

type file struct {
	Email *Email `json:"email,omitempty"`
}

func (s *Store) read() (file, error) {
	var f file
	b, err := os.ReadFile(filepath.Join(s.Dir, File)) // #nosec G304 -- the box's own settings file
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, fmt.Errorf("boxsettings: %w", err)
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("boxsettings: %s doesn't parse: %w", File, err)
	}
	return f, nil
}

// Email is the saved relay, or the default.
func (s *Store) Email() (Email, error) {
	f, err := s.read()
	if err != nil {
		return Email{}, err
	}
	if f.Email == nil {
		return DefaultEmail(), nil
	}
	return *f.Email, nil
}

// SetEmail checks and saves the relay.
func (s *Store) SetEmail(e Email) error {
	if err := e.Check(); err != nil {
		return err
	}
	f, err := s.read()
	if err != nil {
		return err
	}
	f.Email = &e
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("boxsettings: %w", err)
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("boxsettings: %w", err)
	}
	p := filepath.Join(s.Dir, File)
	if err := os.WriteFile(p+".new", append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("boxsettings: %w", err)
	}
	if err := os.Rename(p+".new", p); err != nil {
		return fmt.Errorf("boxsettings: %w", err)
	}
	return nil
}

// Values are every setting the box offers, by name: the saved ones, else
// the defaults.
func (s *Store) Values() (map[string]string, error) {
	e, err := s.Email()
	if err != nil {
		return nil, err
	}
	return e.Values(), nil
}
