// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sshdrun_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshconfig"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshdrun"
)

// requireSshd returns the pinned static sshd from SNEAKERS_TEST_SSHD; the
// Static tools workflow builds it and sets SNEAKERS_REQUIRE_SSHD.
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

func realPaths(t *testing.T, sshd, dir string) sshconfig.Paths {
	t.Helper()
	keys := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	var hostKeys []string
	for name, k := range map[string]any{"ssh_host_ed25519_key": edPriv, "ssh_host_rsa_key": rsaPriv} {
		block, err := ssh.MarshalPrivateKey(k, "")
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(keys, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
		hostKeys = append(hostKeys, p)
	}
	caPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ssh.NewPublicKey(caPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "root_key.pub"), ssh.MarshalAuthorizedKey(ca), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "revoked.krl"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Dir(sshd)
	return sshconfig.Paths{
		ConfigDir: filepath.Join(dir, "ssh"), HostKeys: hostKeys, RevokedKeys: filepath.Join(keys, "revoked.krl"), UserCA: filepath.Join(keys, "root_key.pub"),
		PidFile: "none", Shell: "/bin/true",
		SessionPath: filepath.Join(bin, "sshd-session"), AuthPath: filepath.Join(bin, "sshd-auth"),
	}
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return uint16(ln.Addr().(*net.TCPAddr).Port) // #nosec G115 -- a port
}

func banner(addr string) (string, error) {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	return bufio.NewReader(c).ReadString('\n')
}

func waitBanner(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, err := banner(addr)
		if err == nil && strings.HasPrefix(b, "SSH-2.0-OpenSSH") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("sshd doesn't answer on %s: %q %v", addr, b, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// The pinned sshd starts on the config sshd-run installed, keeps serving
// across a reload, and a render its sshd -t refuses never reaches it.
func TestRealSshdStartsReloadsAndRefuses(t *testing.T) {
	sshd := requireSshd(t)
	r := newRig(t)
	r.writeStore("alice")
	port := freePort(t)
	o := r.options()
	o.Paths = realPaths(t, sshd, r.run)
	o.Port = port
	o.Addresses = func(context.Context) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	o.Check = func(dir string) error { return sshconfig.Check(sshd, dir) }
	o.Start = sshdrun.Exec(sshd, os.Stderr)
	run := sshdrun.New(o)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := run.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	reload := make(chan struct{}, 1)
	go func() { done <- run.Run(ctx, reload) }()
	addr := "127.0.0.1:" + strconv.Itoa(int(port))
	waitBanner(t, addr)

	r.writeStore("alice", "bob")
	before := run.Reloads()
	reload <- struct{}{}
	waitFor(t, func() bool { return run.Reloads() > before })
	waitBanner(t, addr)
	cfg, _ := os.ReadFile(filepath.Join(o.Paths.ConfigDir, "sshd_config"))
	if !strings.Contains(string(cfg), "AllowUsers alice bob\n") {
		t.Fatalf("config:\n%s", cfg)
	}

	// No host keys: sshd -t refuses the render, and the running sshd keeps
	// the config it has.
	for _, k := range o.Paths.HostKeys {
		if err := os.Remove(k); err != nil {
			t.Fatal(err)
		}
	}
	r.writeStore("alice", "bob", "carol")
	before = run.Reloads()
	reload <- struct{}{}
	waitFor(t, func() bool { return run.Reloads() > before })
	if es := r.audit.all(); len(es) != 1 || es[0].Outcome != "refused" {
		t.Fatalf("audit %+v", es)
	}
	cfg, _ = os.ReadFile(filepath.Join(o.Paths.ConfigDir, "sshd_config"))
	if strings.Contains(string(cfg), "carol") {
		t.Fatalf("a refused render was installed:\n%s", cfg)
	}
	// sshd's per-source penalty may refuse the next probe for a second.
	waitBanner(t, addr)
	select {
	case err := <-done:
		t.Fatalf("sshd ended: %v", err)
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("sshd didn't stop")
	}
}
