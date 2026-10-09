// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package sshconfig renders OpenSSH sshd's config from the access store
// (spec 2, Section 3.3). Authentication is public key only, and only a
// certificate the box's root key signed is accepted (TrustedUserCAKeys,
// with no authorized_keys files), for a login name among its principals;
// the closed shell then checks the admin's TOTP code. Render only ever
// writes into a staging directory; sneakers-sshd-run checks the result with
// sshd -t and swaps it in.
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
	"strings"
	"text/template"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
)

// Paths are where sshd finds its files on the box. Tests point them into a
// temporary directory.
type Paths struct {
	// ConfigDir is where the rendered directory lives once swapped in.
	ConfigDir   string
	HostKeys    []string
	RevokedKeys string
	// UserCA is the root key's public half, the only user CA sshd trusts.
	UserCA  string
	PidFile string
	Shell   string
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
		UserCA:      "/var/lib/sneakers/ssh/root_key.pub",
		PidFile:     "none", // sneakers-sshd-run keeps /run/sneakers/sshd.pid
		Shell:       "/usr/bin/sneakers-shell",
	}
}

// Input is what one render needs.
type Input struct {
	ListenAddrs []netip.Addr
	State       access.State
	// Paths default to DefaultPaths when ConfigDir is empty.
	Paths Paths
	// Port is the listen port; 0 is 22. Tests running sshd unprivileged
	// set a high one.
	Port uint16
}

// The algorithms the box offers, the modern set only. Names come from the
// x/crypto constants where it has them.
var (
	// PubkeyAlgorithms are the issued keys' type and its certificate type:
	// the box issues ed25519 keys only.
	PubkeyAlgorithms = []string{ssh.CertAlgoED25519v01, ssh.KeyAlgoED25519}
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

// banner is what sshd sends before authentication: a client without a
// box-issued key and its certificate is refused with only "server sent:
// publickey", so it says where the key comes from and how to send the
// certificate with it.
const banner = `Sneakers-PAM Appliance

SSH takes only keys this box issued, each with its certificate, then a
TOTP code. No passwords. A key sent without its certificate is refused.
No key yet? Sign in to the admin page on :8443, open Access and choose
"Get an SSH key".
OpenSSH:
  ssh -i <key> -o CertificateFile=<key>-cert.pub <your name>@<this box>
PuTTY 0.78 or later, or MobaXterm: use the .ppk download, which has the
certificate in it (Connection > SSH > Auth > Credentials in PuTTY; "Use
private key" under Advanced SSH settings in MobaXterm).
The TOTP prompt comes next, in the menu.
`

type view struct {
	Paths
	Banner            string
	ListenAddrs       []string
	AllowUsers        []string
	PubkeyAlgorithms  []string
	HostKeyAlgorithms []string
	KexAlgorithms     []string
	Ciphers           []string
	MACs              []string
}

// Render writes sshd_config for in into dir. It never touches the live
// configuration. Only admins who can sign in (a password and a TOTP
// secret) may log in.
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
		PubkeyAlgorithms:  PubkeyAlgorithms,
		HostKeyAlgorithms: HostKeyAlgorithms,
		KexAlgorithms:     KexAlgorithms,
		Ciphers:           Ciphers,
		MACs:              MACs,
		Banner:            filepath.Join(p.ConfigDir, "banner"),
	}
	port := in.Port
	if port == 0 {
		port = 22
	}
	for _, a := range in.ListenAddrs {
		v.ListenAddrs = append(v.ListenAddrs, netip.AddrPortFrom(a, port).String())
	}
	for _, a := range in.State.Admins {
		if a.HasCredentials() {
			v.AllowUsers = append(v.AllowUsers, a.Name)
		}
	}
	var cfg bytes.Buffer
	if err := tmpl.Execute(&cfg, v); err != nil {
		return fmt.Errorf("sshconfig: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- sshd's config directory
		return fmt.Errorf("sshconfig: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sshd_config"), cfg.Bytes(), 0o600); err != nil {
		return fmt.Errorf("sshconfig: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "banner"), []byte(banner), 0o644); err != nil { // #nosec G306 -- sshd reads it to send before authentication
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
