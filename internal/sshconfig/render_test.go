// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sshconfig_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshconfig"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// requireSshd returns the pinned static sshd from SNEAKERS_TEST_SSHD. The
// Static tools workflow builds it and sets SNEAKERS_REQUIRE_SSHD, which
// turns a missing sshd into a failure instead of a skip.
func requireSshd(t *testing.T) string {
	t.Helper()
	p := os.Getenv("SNEAKERS_TEST_SSHD")
	if p == "" {
		if os.Getenv("SNEAKERS_REQUIRE_SSHD") != "" {
			t.Fatal("SNEAKERS_TEST_SSHD isn't set and SNEAKERS_REQUIRE_SSHD is")
		}
		t.Skip("SNEAKERS_TEST_SSHD isn't set; the Static tools workflow runs this test against the pinned sshd")
	}
	return p
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func edKeyLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	mustNoErr(t, err)
	pk, err := ssh.NewPublicKey(pub)
	mustNoErr(t, err)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

func twoAdmins(t *testing.T) access.State {
	t.Helper()
	s := access.State{NextUID: access.FirstUID}
	now := time.Date(2026, 10, 5, 14, 0, 0, 0, time.UTC)
	for _, n := range []string{"alice", "bob"} {
		a := s.AddAdmin(n, access.RoleOwner, "setup", now)
		k, err := access.ParseLoginKey(edKeyLine(t))
		mustNoErr(t, err)
		a.Keys = append(a.Keys, access.AdminKey{Key: k, Added: now, AddedBy: n, Via: access.ViaIssued, Serial: 1})
		a.Password = &access.Password{Hash: "$argon2id$test", Changed: now}
		a.TOTP = &access.TOTP{Sealed: "test", Added: now}
	}
	return s
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	mustNoErr(t, err)
	return string(b)
}

var algoLines = map[string][]string{
	"PubkeyAcceptedAlgorithms": sshconfig.PubkeyAlgorithms,
	"HostKeyAlgorithms":        sshconfig.HostKeyAlgorithms,
	"KexAlgorithms":            sshconfig.KexAlgorithms,
	"Ciphers":                  sshconfig.Ciphers,
	"MACs":                     sshconfig.MACs,
}

// withoutAlgorithms checks the algorithm lines against the lists and drops
// them, so the golden files hold everything else. The lists name OpenSSH's
// own extension algorithms, which aren't kept in fixture files.
func withoutAlgorithms(t *testing.T, cfg string) string {
	t.Helper()
	var kept []string
	seen := map[string]bool{}
	for _, line := range strings.Split(cfg, "\n") {
		kw, val, _ := strings.Cut(line, " ")
		if want, ok := algoLines[kw]; ok {
			if val != strings.Join(want, ",") {
				t.Fatalf("%s is %q", kw, val)
			}
			seen[kw] = true
			continue
		}
		kept = append(kept, line)
	}
	for kw := range algoLines {
		if !seen[kw] {
			t.Fatalf("no %s line", kw)
		}
	}
	return strings.Join(kept, "\n")
}

func golden(t *testing.T, got, path string) {
	t.Helper()
	if *update {
		mustNoErr(t, os.WriteFile(path, []byte(got), 0o600))
	}
	if want := readFile(t, path); got != want {
		t.Fatalf("differs from %s:\n%s", path, got)
	}
}

func TestRenderGolden(t *testing.T) {
	dir := t.TempDir()
	in := sshconfig.Input{ListenAddrs: addrs("192.0.2.10", "2001:db8::10"), State: twoAdmins(t)}
	mustNoErr(t, sshconfig.Render(in, dir))
	golden(t, withoutAlgorithms(t, readFile(t, filepath.Join(dir, "sshd_config"))), "testdata/admin.golden")
}

func TestOnlyRootKeyCertificatesAndNoPasswords(t *testing.T) {
	dir := t.TempDir()
	mustNoErr(t, sshconfig.Render(sshconfig.Input{ListenAddrs: addrs("192.0.2.10"), State: twoAdmins(t)}, dir))
	cfg := readFile(t, filepath.Join(dir, "sshd_config"))
	for _, banned := range []string{"\nSubsystem", "PasswordAuthentication yes", "KbdInteractiveAuthentication yes", "DisableForwarding no", "Match User", "AuthorizedKeysCommand"} {
		if strings.Contains(cfg, banned) {
			t.Fatalf("config contains %q", banned)
		}
	}
	for _, want := range []string{"AuthenticationMethods publickey\n", "AuthorizedKeysFile none\n", "TrustedUserCAKeys /var/lib/sneakers/ssh/root_key.pub\n",
		"RevokedKeys /var/lib/sneakers/ssh/revoked.krl\n", "PermitRootLogin no\n", "ExposeAuthInfo yes\n", "ForceCommand /usr/bin/sneakers-shell\n", "AllowUsers alice bob\n"} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config lacks %q", want)
		}
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 {
		t.Fatalf("Render wrote more than sshd_config and the banner: %v", ents)
	}
}

func TestOnlyAdminsWhoCanSignInMayLogIn(t *testing.T) {
	s := twoAdmins(t)
	s.Admins[1].TOTP = nil
	dir := t.TempDir()
	mustNoErr(t, sshconfig.Render(sshconfig.Input{ListenAddrs: addrs("192.0.2.10"), State: s}, dir))
	if cfg := readFile(t, filepath.Join(dir, "sshd_config")); !strings.Contains(cfg, "AllowUsers alice\n") {
		t.Fatalf("an invited admin may log in:\n%s", cfg)
	}
	s.Admins[0].TOTP = nil
	mustNoErr(t, sshconfig.Render(sshconfig.Input{ListenAddrs: addrs("192.0.2.10"), State: s}, dir))
	if cfg := readFile(t, filepath.Join(dir, "sshd_config")); !strings.Contains(cfg, "DenyUsers *\n") || strings.Contains(cfg, "AllowUsers") {
		t.Fatalf("with nobody able to sign in:\n%s", cfg)
	}
}

// testPaths points every file sshd reads into dir, with real host keys.
func testPaths(t *testing.T, sshd, dir string) sshconfig.Paths {
	t.Helper()
	keys := filepath.Join(dir, "keys")
	mustNoErr(t, os.MkdirAll(keys, 0o700))
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	mustNoErr(t, err)
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 3072)
	mustNoErr(t, err)
	var hostKeys []string
	for name, k := range map[string]any{"ssh_host_ed25519_key": edPriv, "ssh_host_rsa_key": rsaPriv} {
		block, err := ssh.MarshalPrivateKey(k, "")
		mustNoErr(t, err)
		p := filepath.Join(keys, name)
		mustNoErr(t, os.WriteFile(p, pem.EncodeToMemory(block), 0o600))
		hostKeys = append(hostKeys, p)
	}
	ca := filepath.Join(keys, "root_key.pub")
	mustNoErr(t, os.WriteFile(ca, []byte(edKeyLine(t)+"\n"), 0o644))
	krl := filepath.Join(keys, "revoked.krl")
	mustNoErr(t, os.WriteFile(krl, nil, 0o644))
	bin := filepath.Dir(sshd)
	return sshconfig.Paths{
		ConfigDir: filepath.Join(dir, "ssh"), HostKeys: hostKeys, RevokedKeys: krl, UserCA: ca,
		PidFile: filepath.Join(dir, "sshd.pid"), Shell: "/bin/true",
		SessionPath: filepath.Join(bin, "sshd-session"), AuthPath: filepath.Join(bin, "sshd-auth"),
	}
}

func TestRenderPassesSshdT(t *testing.T) {
	sshd := requireSshd(t)
	paths := testPaths(t, sshd, t.TempDir())
	none := twoAdmins(t)
	for i := range none.Admins {
		none.Admins[i].TOTP = nil
	}
	for name, st := range map[string]access.State{"admins": twoAdmins(t), "nobody": none} {
		t.Run(name, func(t *testing.T) {
			dir := paths.ConfigDir
			mustNoErr(t, os.RemoveAll(dir))
			mustNoErr(t, sshconfig.Render(sshconfig.Input{ListenAddrs: addrs("192.0.2.10", "2001:db8::10"), State: st, Paths: paths}, dir))
			mustNoErr(t, sshconfig.Check(sshd, dir))
		})
	}
}

func TestCheckRefusesABadConfig(t *testing.T) {
	sshd := requireSshd(t)
	dir := t.TempDir()
	mustNoErr(t, os.WriteFile(filepath.Join(dir, "sshd_config"), []byte("NotAnOption yes\n"), 0o600))
	if err := sshconfig.Check(sshd, dir); err == nil {
		t.Fatal("sshd -t accepted an unknown option")
	}
}

// A client with no box-issued key is refused with "server sent: publickey";
// the banner sshd sends before that says to get a key on :8443 first.
func TestTheBannerSaysToGetAKeyFirst(t *testing.T) {
	dir := t.TempDir()
	mustNoErr(t, sshconfig.Render(sshconfig.Input{ListenAddrs: addrs("192.0.2.10"), State: twoAdmins(t)}, dir))
	if cfg := readFile(t, filepath.Join(dir, "sshd_config")); !strings.Contains(cfg, "\nBanner /run/sneakers/ssh/banner\n") {
		t.Fatalf("no Banner line:\n%s", cfg)
	}
	b := readFile(t, filepath.Join(dir, "banner"))
	for _, want := range []string{"only keys this box issued", ":8443", "Access", "Get an SSH key", "TOTP"} {
		if !strings.Contains(b, want) {
			t.Errorf("the banner lacks %q:\n%s", want, b)
		}
	}
}

// A box-issued key logs in only with its certificate: the banner gives the
// OpenSSH command that loads it, the PuTTY and MobaXterm way, and says the
// TOTP prompt comes next.
func TestTheBannerSaysHowToSendTheCertificate(t *testing.T) {
	dir := t.TempDir()
	mustNoErr(t, sshconfig.Render(sshconfig.Input{ListenAddrs: addrs("192.0.2.10"), State: twoAdmins(t)}, dir))
	b := readFile(t, filepath.Join(dir, "banner"))
	for _, want := range []string{
		"ssh -i <key> -o CertificateFile=<key>-cert.pub <your name>@<this box>",
		".ppk", "PuTTY 0.78", "MobaXterm", "certificate", "TOTP",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("the banner lacks %q:\n%s", want, b)
		}
	}
	for _, l := range strings.Split(b, "\n") {
		if len(l) > 78 {
			t.Errorf("a banner line is %d characters: %q", len(l), l)
		}
	}
}

// A host key with a certificate next to it (<key>-cert.pub, which accessd
// signs with the host CA) is presented with it: a HostCertificate line per
// certificate that exists, none for a key without one.
func TestAHostKeysCertificateIsPresented(t *testing.T) {
	keys := t.TempDir()
	p := sshconfig.DefaultPaths()
	p.ConfigDir = filepath.Join(t.TempDir(), "ssh")
	p.HostKeys = []string{filepath.Join(keys, "ssh_host_ed25519_key"), filepath.Join(keys, "ssh_host_rsa_key")}
	mustNoErr(t, os.WriteFile(p.HostKeys[0]+"-cert.pub", []byte(ssh.CertAlgoED25519v01+" AAAA\n"), 0o644))
	dir := t.TempDir()
	mustNoErr(t, sshconfig.Render(sshconfig.Input{ListenAddrs: addrs("192.0.2.10"), State: twoAdmins(t), Paths: p}, dir))
	cfg := readFile(t, filepath.Join(dir, "sshd_config"))
	if !strings.Contains(cfg, "HostCertificate "+p.HostKeys[0]+"-cert.pub\n") || strings.Contains(cfg, "HostCertificate "+p.HostKeys[1]) {
		t.Fatalf("config:\n%s", cfg)
	}
}
