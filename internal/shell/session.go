// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell

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

// Session is who is on the other end of an SSH login: the admin, the key
// that authenticated the connection and the client's address. The daemons
// check the key belongs to the caller's uid before trusting it.
type Session struct {
	Admin          string
	KeyFingerprint string
	Source         string
}

// maxAuthInfo bounds the SSH_USER_AUTH file sshd writes: one line per
// authentication method, so a few kilobytes at most.
const maxAuthInfo = 64 * 1024

// SessionFromSSH reads the session sshd describes in the environment:
// SSH_USER_AUTH (ExposeAuthInfo) names a file holding "publickey <key>" for
// the key that signed in, and SSH_CONNECTION starts with the client's
// address. Exactly one public key must have authenticated.
func SessionFromSSH(getenv func(string) string, admin string) (Session, error) {
	s := Session{Admin: admin}
	conn := strings.Fields(getenv("SSH_CONNECTION"))
	if len(conn) == 0 {
		return s, fmt.Errorf("SSH_CONNECTION isn't set")
	}
	src, err := netip.ParseAddr(conn[0])
	if err != nil {
		return s, fmt.Errorf("SSH_CONNECTION: %w", err)
	}
	s.Source = src.String()
	path := getenv("SSH_USER_AUTH")
	if path == "" {
		return s, fmt.Errorf("SSH_USER_AUTH isn't set")
	}
	f, err := os.Open(path) // #nosec G304 -- the file sshd names for this session
	if err != nil {
		return s, fmt.Errorf("reading the session's authentication info: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := io.ReadAll(io.LimitReader(f, maxAuthInfo+1))
	if err != nil {
		return s, fmt.Errorf("reading the session's authentication info: %w", err)
	}
	if len(info) > maxAuthInfo {
		return s, fmt.Errorf("the session's authentication info is longer than %d bytes", maxAuthInfo)
	}
	var fps []string
	sc := bufio.NewScanner(bytes.NewReader(info))
	sc.Buffer(make([]byte, 0, 4096), maxAuthInfo+1)
	for sc.Scan() {
		method, rest, _ := strings.Cut(sc.Text(), " ")
		if method != "publickey" {
			continue
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rest))
		if err != nil {
			return s, fmt.Errorf("the session's key doesn't parse: %w", err)
		}
		fps = append(fps, ssh.FingerprintSHA256(pk))
	}
	if err := sc.Err(); err != nil {
		return s, fmt.Errorf("reading the session's authentication info: %w", err)
	}
	if len(fps) != 1 {
		return s, fmt.Errorf("the session names %d public keys, not one", len(fps))
	}
	s.KeyFingerprint = fps[0]
	return s, nil
}
