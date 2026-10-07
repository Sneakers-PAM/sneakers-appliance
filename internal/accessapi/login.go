// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessapi

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Login is what sshd says about the SSH login a forced command runs for:
// the one public key (or certificate) that authenticated it, and the
// client's address.
type Login struct {
	// Key is the key or certificate; KeyLine is it in authorized_keys
	// form, as sshd wrote it.
	Key     ssh.PublicKey
	KeyLine string
	Source  string
}

// maxAuthInfo bounds the SSH_USER_AUTH file sshd writes: one line per
// authentication method, so a few kilobytes at most.
const maxAuthInfo = 64 * 1024

// LoginFromSSH reads the login sshd describes in the environment:
// SSH_USER_AUTH (ExposeAuthInfo) names a file holding "publickey <key>" for
// the key that signed in, and SSH_CONNECTION starts with the client's
// address. Exactly one public key must have authenticated.
func LoginFromSSH(getenv func(string) string) (Login, error) {
	var l Login
	conn := strings.Fields(getenv("SSH_CONNECTION"))
	if len(conn) == 0 {
		return l, fmt.Errorf("SSH_CONNECTION isn't set")
	}
	src, err := netip.ParseAddr(conn[0])
	if err != nil {
		return l, fmt.Errorf("SSH_CONNECTION: %w", err)
	}
	l.Source = src.String()
	path := getenv("SSH_USER_AUTH")
	if path == "" {
		return l, fmt.Errorf("SSH_USER_AUTH isn't set")
	}
	f, err := os.Open(path) // #nosec G304 -- the file sshd names for this session
	if err != nil {
		return l, fmt.Errorf("reading the session's authentication info: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := io.ReadAll(io.LimitReader(f, maxAuthInfo+1))
	if err != nil {
		return l, fmt.Errorf("reading the session's authentication info: %w", err)
	}
	if len(info) > maxAuthInfo {
		return l, fmt.Errorf("the session's authentication info is longer than %d bytes", maxAuthInfo)
	}
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(info))
	sc.Buffer(make([]byte, 0, 4096), maxAuthInfo+1)
	for sc.Scan() {
		method, rest, _ := strings.Cut(sc.Text(), " ")
		if method != "publickey" {
			continue
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rest))
		if err != nil {
			return l, fmt.Errorf("the session's key doesn't parse: %w", err)
		}
		l.Key, l.KeyLine = pk, strings.TrimSpace(rest)
		n++
	}
	if err := sc.Err(); err != nil {
		return l, fmt.Errorf("reading the session's authentication info: %w", err)
	}
	if n != 1 {
		return Login{Source: l.Source}, fmt.Errorf("the session names %d public keys, not one", n)
	}
	return l, nil
}
