// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package boxname is the box's own name, sneakers-<8 hex>: made once and
// kept on the state volume, so it survives reboots and updates. It is the
// kernel host name while no name is configured or offered by DHCP, and the
// k0s node name (docs/network.md, docs/k0s.md).
package boxname

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var shape = regexp.MustCompile(`^sneakers-[0-9a-f]{8}$`)

// Path is the name's file under the state volume's /var/lib/sneakers.
func Path(stateDir string) string { return filepath.Join(stateDir, "box-name") }

// legacyPath is where k0s-interim kept the node name before the base layer
// owned it; a box that has one keeps it, so its etcd member name stays.
func legacyPath(stateDir string) string { return filepath.Join(stateDir, "k0s", "node-name") }

func read(path string) string {
	b, err := os.ReadFile(path) // #nosec G304 -- a file under the state volume
	if err != nil {
		return ""
	}
	if n := strings.TrimSpace(string(b)); shape.MatchString(n) {
		return n
	}
	return ""
}

// Ensure returns the box's name, making it the first time: the earlier k0s
// node name when there is one, else a new random one. A file that doesn't
// hold a name is replaced.
func Ensure(stateDir string) (string, error) {
	p := Path(stateDir)
	if n := read(p); n != "" {
		return n, nil
	}
	n := read(legacyPath(stateDir))
	if n == "" {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("boxname: no randomness: %w", err)
		}
		n = "sneakers-" + hex.EncodeToString(b[:])
	}
	if err := writeSynced(p, n+"\n"); err != nil {
		return "", fmt.Errorf("boxname: %w", err)
	}
	return n, nil
}

// writeSynced survives a power cut: a temporary file, fsync, rename, then
// fsync the directory.
func writeSynced(p, s string) error {
	tmp := p + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) // #nosec G302 G304 -- the box's name isn't secret
	if err != nil {
		return err
	}
	_, werr := f.WriteString(s)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(p))
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
