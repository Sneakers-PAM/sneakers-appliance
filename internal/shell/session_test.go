// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/shell"
)

func pubKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func authFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "auth")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestSessionFromSSH(t *testing.T) {
	pk := pubKey(t)
	line := "publickey " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
	s, err := shell.SessionFromSSH(envOf(map[string]string{
		"SSH_USER_AUTH":  authFile(t, line+"\n"),
		"SSH_CONNECTION": "192.0.2.50 51234 192.0.2.10 22",
	}), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if s.Admin != "alice" || s.Source != "192.0.2.50" || s.KeyFingerprint != ssh.FingerprintSHA256(pk) {
		t.Fatalf("%+v", s)
	}
}

func TestSessionFromSSHRefuses(t *testing.T) {
	pk := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey(t))))
	conn := "192.0.2.50 51234 192.0.2.10 22"
	for name, env := range map[string]map[string]string{
		"no auth info":     {"SSH_CONNECTION": conn},
		"no connection":    {"SSH_USER_AUTH": authFile(t, "publickey "+pk+"\n")},
		"not a key":        {"SSH_USER_AUTH": authFile(t, "publickey not-a-key\n"), "SSH_CONNECTION": conn},
		"no publickey":     {"SSH_USER_AUTH": authFile(t, "password\n"), "SSH_CONNECTION": conn},
		"two keys":         {"SSH_USER_AUTH": authFile(t, "publickey "+pk+"\npublickey "+pk+"\n"), "SSH_CONNECTION": conn},
		"bad source":       {"SSH_USER_AUTH": authFile(t, "publickey "+pk+"\n"), "SSH_CONNECTION": "nope 1 2 3"},
		"missing the file": {"SSH_USER_AUTH": filepath.Join(t.TempDir(), "gone"), "SSH_CONNECTION": conn},
	} {
		if _, err := shell.SessionFromSSH(envOf(env), "alice"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
