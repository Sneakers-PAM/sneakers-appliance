// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sshdrun_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/elevation"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/rootkey"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshconfig"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshdrun"
)

type sealer struct{ items map[string][]byte }

func (s *sealer) Seal(n string, b []byte) error { s.items[n] = slices.Clone(b); return nil }

func (s *sealer) Unseal(n string) ([]byte, bool, error) {
	b, ok := s.items[n]
	return slices.Clone(b), ok, nil
}

func signerAndPub(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, s.PublicKey()
}

func tryLogin(t *testing.T, addr, name string, auth ssh.Signer) error {
	t.Helper()
	cfg := &ssh.ClientConfig{User: name, Auth: []ssh.AuthMethod{ssh.PublicKeys(auth)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second} // #nosec G106 -- a throwaway test sshd
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return err
	}
	return c.Close()
}

// The pinned sshd lets in a certificate the root key signed for the login
// name, and refuses a plain key, a certificate for another name, an expired
// one and a revoked one.
func TestRealSshdTakesOnlyTheRootKeysCertificates(t *testing.T) {
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

	now := time.Now()
	issue := func(name string, serial uint64, before time.Time) ssh.Signer {
		s, pub := signerAndPub(t)
		cert, err := root.IssueUserCert(pub, name, serial, now.Add(-time.Minute), before)
		if err != nil {
			t.Fatal(err)
		}
		cs, err := ssh.NewCertSigner(cert, s)
		if err != nil {
			t.Fatal(err)
		}
		return cs
	}
	if err := tryLogin(t, addr, u.Username, issue(u.Username, 1, now.Add(time.Hour))); err != nil {
		t.Fatalf("an issued certificate was refused: %v", err)
	}
	plain, _ := signerAndPub(t)
	for name, s := range map[string]ssh.Signer{
		"a plain key":            plain,
		"a certificate for zed":  issue("zed", 2, now.Add(time.Hour)),
		"an expired certificate": issue(u.Username, 3, now.Add(-30*time.Second)),
	} {
		if err := tryLogin(t, addr, u.Username, s); err == nil {
			t.Errorf("%s logged in", name)
		}
	}
	revokedCert := issue(u.Username, 4, now.Add(time.Hour))
	krl := elevation.MarshalKRL(root.PublicKey(), []uint64{4}, nil, 1, now)
	if err := os.WriteFile(o.Paths.RevokedKeys, krl, 0o644); err != nil { // #nosec G306 -- the test's revocation list
		t.Fatal(err)
	}
	if err := tryLogin(t, addr, u.Username, revokedCert); err == nil {
		t.Error("a revoked certificate logged in")
	}
	cancel()
	<-done
}
