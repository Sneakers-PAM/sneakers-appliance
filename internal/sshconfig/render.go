// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package sshconfig renders what OpenSSH sshd reads: sshd_config, each
// admin's authorized_keys and the maint principals file, from the access
// store (spec 2, Section 3.3). Render only ever writes into a staging
// directory; sneakers-sshd-run checks the result with sshd -t and swaps it
// in.
package sshconfig

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"text/template"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
)

// Mode is which accounts sshd lets in.
type Mode string

const (
	// EnrolMode is first-boot step 3: only the enrol account exists.
	EnrolMode Mode = "enrol"
	// AdminMode is every admin into the closed shell, and maint for
	// elevation.
	AdminMode Mode = "admin"
)

// Paths are where sshd finds its files on the box. Tests point them into a
// temporary directory.
type Paths struct {
	// ConfigDir is where the rendered directory lives once swapped in.
	ConfigDir   string
	HostKeys    []string
	RevokedKeys string
	UserCA      string
	PidFile     string
	Shell       string
	Elevated    string
	Enrol       string
	EnrolKeys   string
	// SessionPath and AuthPath override where sshd finds sshd-session and
	// sshd-auth; empty keeps the built-in /usr/libexec/openssh paths.
	SessionPath string
	AuthPath    string
}

// DefaultPaths are the appliance's paths.
func DefaultPaths() Paths {
	return Paths{
		ConfigDir:   "/run/sneakers/ssh",
		HostKeys:    []string{"/var/lib/sneakers/ssh/ssh_host_ed25519_key", "/var/lib/sneakers/ssh/ssh_host_rsa_key"},
		RevokedKeys: "/var/lib/sneakers/ssh/revoked.krl",
		UserCA:      "/var/lib/sneakers/ssh/user_ca.pub",
		PidFile:     "none", // sneakers-sshd-run keeps /run/sneakers/sshd.pid
		Shell:       "/usr/bin/sneakers-shell",
		Elevated:    "/usr/libexec/sneakers-elevated",
		Enrol:       "/usr/libexec/sneakers-enrol",
		EnrolKeys:   "/usr/libexec/sneakers-enrol-keys",
	}
}

// Input is what one render needs.
type Input struct {
	ListenAddrs []netip.Addr
	Mode        Mode
	// EnrolOpen renders the enrol block in admin mode too (Recover access,
	// or another admin's keys added on the console). EnrolMode implies it.
	EnrolOpen bool
	State     access.State
	// Principals are the open elevation principals (elev-<id>) maint
	// accepts.
	Principals []string
	// Paths default to DefaultPaths when ConfigDir is empty.
	Paths Paths
	// Port is the listen port; 0 is 22. Tests running sshd unprivileged
	// set a high one.
	Port uint16
}

// The algorithms the box offers, the modern set only. Names come from the
// x/crypto constants where it has them.
var (
	// PubkeyAlgorithms are the login key types plus the certificate types
	// an elevation certificate for each of them can have.
	PubkeyAlgorithms = []string{
		ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoSKECDSA256,
		ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
		ssh.CertAlgoED25519v01, ssh.CertAlgoSKED25519v01,
		ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoSKECDSA256v01,
		ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01,
	}
	// HostKeyAlgorithms match the ed25519 and RSA host keys.
	HostKeyAlgorithms = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	// KexAlgorithms are the hybrid post-quantum exchanges and curve25519.
	KexAlgorithms = []string{ssh.KeyExchangeMLKEM768X25519, "sntrup761x25519-sha512", ssh.KeyExchangeCurve25519}
	// Ciphers are the AEAD ciphers.
	Ciphers = []string{ssh.CipherChaCha20Poly1305, ssh.CipherAES256GCM, ssh.CipherAES128GCM}
	// MACs are the encrypt-then-MAC forms (the AEAD ciphers don't use one).
	MACs = []string{ssh.HMACSHA512ETM, ssh.HMACSHA256ETM}
)

//go:embed sshd_config.tmpl
var configTemplate string

var tmpl = template.Must(template.New("sshd_config").Funcs(template.FuncMap{"join": strings.Join}).Parse(configTemplate))

type view struct {
	Paths
	ListenAddrs       []string
	AuthorizedKeysDir string
	PrincipalsDir     string
	EnrolOpen         bool
	AllowUsers        []string
	PubkeyAlgorithms  []string
	HostKeyAlgorithms []string
	KexAlgorithms     []string
	Ciphers           []string
	MACs              []string
}

// Render writes sshd_config, authorized_keys/<admin> and principals/maint
// for in into dir. It never touches the live configuration.
func Render(in Input, dir string) error {
	p := in.Paths
	if p.ConfigDir == "" {
		p = DefaultPaths()
	}
	if len(in.ListenAddrs) == 0 {
		return fmt.Errorf("sshconfig: no listen address")
	}
	v := view{
		Paths:             p,
		AuthorizedKeysDir: filepath.Join(p.ConfigDir, "authorized_keys"),
		PrincipalsDir:     filepath.Join(p.ConfigDir, "principals"),
		EnrolOpen:         in.Mode == EnrolMode || in.EnrolOpen,
		PubkeyAlgorithms:  PubkeyAlgorithms,
		HostKeyAlgorithms: HostKeyAlgorithms,
		KexAlgorithms:     KexAlgorithms,
		Ciphers:           Ciphers,
		MACs:              MACs,
	}
	port := in.Port
	if port == 0 {
		port = 22
	}
	for _, a := range in.ListenAddrs {
		v.ListenAddrs = append(v.ListenAddrs, netip.AddrPortFrom(a, port).String())
	}
	switch in.Mode {
	case EnrolMode:
		v.AllowUsers = []string{"enrol"}
	case AdminMode:
		for _, a := range in.State.Admins {
			v.AllowUsers = append(v.AllowUsers, a.Name)
		}
		v.AllowUsers = append(v.AllowUsers, "maint")
		if in.EnrolOpen {
			v.AllowUsers = append(v.AllowUsers, "enrol")
		}
	default:
		return fmt.Errorf("sshconfig: unknown mode %q", in.Mode)
	}
	var cfg bytes.Buffer
	if err := tmpl.Execute(&cfg, v); err != nil {
		return fmt.Errorf("sshconfig: %w", err)
	}
	for _, sub := range []string{"authorized_keys", "principals"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil { // #nosec G301 -- sshd reads them as the logging-in user
			return fmt.Errorf("sshconfig: %w", err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "sshd_config"), cfg.Bytes(), 0o600); err != nil {
		return fmt.Errorf("sshconfig: %w", err)
	}
	if in.Mode == AdminMode {
		for _, a := range in.State.Admins {
			if err := writeKeys(filepath.Join(dir, "authorized_keys", a.Name), a.Keys); err != nil {
				return err
			}
		}
	}
	principals := slices.Clone(in.Principals)
	slices.Sort(principals)
	body := strings.Join(principals, "\n")
	if body != "" {
		body += "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "principals", "maint"), []byte(body), 0o644); err != nil { // #nosec G306 -- sshd reads it as the logging-in user
		return fmt.Errorf("sshconfig: %w", err)
	}
	return nil
}

// Every key is restricted (no forwarding, no user rc) with the pty given
// back, since the interactive closed shell needs one.
func writeKeys(path string, keys []access.AdminKey) error {
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "restrict,pty %s\n", k.PublicKey)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil { // #nosec G306 -- sshd reads it as the logging-in user
		return fmt.Errorf("sshconfig: %w", err)
	}
	return nil
}

// Check runs sshdPath -t on the sshd_config in dir: the rendered config is
// swapped in only when the pinned sshd accepts it.
func Check(sshdPath, dir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sshdPath, "-t", "-f", filepath.Join(dir, "sshd_config")) // #nosec G204 -- the pinned sshd on a config we rendered
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sshconfig: sshd -t refused the config: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Principal is the maint principal an elevation request opens.
func Principal(requestID string) string { return "elev-" + requestID }
