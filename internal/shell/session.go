// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/accessapi"
)

// Session is who is on the other end of an SSH login: the admin, the key
// that authenticated the connection and the client's address. The daemons
// check the key belongs to the caller's uid before trusting it.
type Session struct {
	Admin          string
	KeyFingerprint string
	Source         string
}

// SessionFromSSH reads the session sshd describes in the environment
// (accessapi.LoginFromSSH): the key that signed in and the client's
// address.
func SessionFromSSH(getenv func(string) string, admin string) (Session, error) {
	l, err := accessapi.LoginFromSSH(getenv)
	s := Session{Admin: admin, Source: l.Source}
	if err != nil {
		return s, err
	}
	s.KeyFingerprint = ssh.FingerprintSHA256(l.Key)
	return s, nil
}
