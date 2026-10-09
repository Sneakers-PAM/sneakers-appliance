// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sshdrun_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessd"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootkey"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshconfig"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshdrun"
)

// The pinned sshd presents the host certificate the host CA signed, so a
// client whose known_hosts holds only the box's @cert-authority line
// trusts it with strict host key checking and no prompt; with the line for
// another CA it refuses. With SNEAKERS_TEST_SSH set, OpenSSH's ssh does the
// same with -o StrictHostKeyChecking=yes.
func TestRealSshdPresentsItsHostCertificate(t *testing.T) {
	sshd := requireSshd(t)
	u, err := user.Current()
	if err != nil || !access.ValidName(u.Username) {
		t.Skipf("the test user %q can't be an admin name", u.Username)
	}
	r := newRig(t)
	r.writeStore(u.Username)
	o := r.options()
	o.Paths = realPaths(t, sshd, r.run)
	keys := filepath.Dir(o.Paths.UserCA)
	root, err := rootkey.Load(&sealer{items: map[string][]byte{}}, keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(keys, rootkey.PublicFile), o.Paths.UserCA); err != nil {
		t.Fatal(err)
	}
	for _, k := range o.Paths.HostKeys {
		signer, err := ssh.ParsePrivateKey(mustRead(t, k))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(k+".pub", ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644); err != nil { // #nosec G306 -- a public key
			t.Fatal(err)
		}
	}
	if _, err := accessd.SignHostCerts(root, keys, []string{"127.0.0.1"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
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
	go func() { done <- run.Run(ctx, nil) }()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	waitBanner(t, addr)

	_, userKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(userKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := root.IssueUserCert(s.PublicKey(), u.Username, 1, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cs, err := ssh.NewCertSigner(cert, s)
	if err != nil {
		t.Fatal(err)
	}
	// On the box sshd is on 22 and the line names the bare host; this
	// sshd's test port goes in brackets.
	pattern := "[127.0.0.1]:" + strconv.Itoa(int(port))
	line := "@cert-authority " + pattern + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(root.HostCAPublicKey()))) + "\n"
	known := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(known, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	cb, err := knownhosts.New(known)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ClientConfig{User: u.Username, Auth: []ssh.AuthMethod{ssh.PublicKeys(cs)}, HostKeyCallback: cb, Timeout: 5 * time.Second,
		HostKeyAlgorithms: []string{ssh.CertAlgoED25519v01}}
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("the box's host certificate wasn't trusted from the @cert-authority line: %v", err)
	}
	_ = c.Close()
	other, _ := signerAndPub(t)
	wrong := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(wrong, []byte("@cert-authority "+pattern+" "+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other.PublicKey())))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cbWrong, _ := knownhosts.New(wrong)
	cfg.HostKeyCallback = cbWrong
	if c, err := ssh.Dial("tcp", addr, cfg); err == nil {
		_ = c.Close()
		t.Fatal("a host certificate from another CA was trusted")
	}

	if client := os.Getenv("SNEAKERS_TEST_SSH"); client != "" {
		dir := t.TempDir()
		key := filepath.Join(dir, "id")
		block, err := ssh.MarshalPrivateKey(userKey, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(key, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(key+"-cert.pub", ssh.MarshalAuthorizedKey(cert), 0o600); err != nil {
			t.Fatal(err)
		}
		args := []string{"-F", "none", "-p", strconv.Itoa(int(port)), "-i", key, "-o", "CertificateFile=" + key + "-cert.pub",
			"-o", "UserKnownHostsFile=" + known, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes",
			u.Username + "@127.0.0.1", "true"}
		if out, err := exec.CommandContext(ctx, client, args...).CombinedOutput(); err != nil || strings.Contains(string(out), "authenticity") { // #nosec G204 -- the test's ssh
			t.Fatalf("OpenSSH with only the @cert-authority line: %v\n%s", err, out)
		}
	}
	cancel()
	<-done
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p) // #nosec G304 -- a test file
	if err != nil {
		t.Fatal(err)
	}
	return b
}
