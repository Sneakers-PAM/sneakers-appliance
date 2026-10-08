// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package accounts renders the Unix account files from the access store.
// /etc is read-only in the root image; /etc/passwd, /etc/group and
// /etc/shadow are symlinks into /run/sneakers/accounts/, which accessd
// rewrites at start and on every change (spec 2, Section 3.2).
package accounts

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
)

// The paths the rendered accounts point at.
const (
	Dir         = "/run/sneakers/accounts"
	HomeRoot    = "/run/sneakers/home"
	ShellPath   = "/usr/bin/sneakers-shell"
	NoLogin     = "/usr/sbin/nologin"
	privsepHome = "/run/sneakers/sshd-empty"
)

// Account is one passwd line.
type Account struct {
	Name  string
	UID   int
	GID   int
	Gecos string
	Home  string
	Shell string
}

// The fixed system accounts. No login reaches a uid 0 account: the root
// shell runs under accessd, through the challenge and its code.
var system = []Account{
	{"root", 0, 0, "root", "/", NoLogin},
	{"sshd", 100, 100, "sshd privilege separation", privsepHome, NoLogin},
	{"sshkeys", 101, 101, "sshd keys command", "/", NoLogin},
	{"osadmin", OsadminUID, OsadminUID, "appliance admin on 8443", "/", NoLogin},
}

var nobody = Account{"nobody", 65534, 65534, "nobody", "/", NoLogin}

// ServiceUser returns the fixed system account a service may run as: one
// with its own uid, so never root.
func ServiceUser(name string) (Account, bool) {
	for _, a := range system {
		if a.Name == name && a.UID != 0 {
			return a, true
		}
	}
	return Account{}, false
}

// OsadminUID is the uid sneakers-osadmin runs as.
const OsadminUID = 102

// Accounts returns every account for s, in file order.
func Accounts(s access.State) []Account {
	out := slices.Clone(system)
	out = append(out, nobody)
	for _, a := range s.Admins {
		out = append(out, Account{Name: a.Name, UID: a.UID, GID: a.UID, Gecos: string(a.Role), Home: HomeRoot + "/" + a.Name, Shell: ShellPath})
	}
	return out
}

// Render writes passwd, group and shadow for s into dir, each through a
// tmp file and a rename, so a reader sees the old file or the new one.
func Render(s access.State, dir string) error {
	accts := Accounts(s)
	var passwd, group, shadow strings.Builder
	seenGID := map[int]bool{}
	for _, a := range accts {
		fmt.Fprintf(&passwd, "%s:x:%d:%d:%s:%s:%s\n", a.Name, a.UID, a.GID, a.Gecos, a.Home, a.Shell)
		// No account has a password, so none can be set or guessed.
		fmt.Fprintf(&shadow, "%s:*:::::::\n", a.Name)
		if !seenGID[a.GID] {
			seenGID[a.GID] = true
			name := a.Name
			if a.Name == "nobody" {
				name = "nogroup"
			}
			fmt.Fprintf(&group, "%s:x:%d:\n", name, a.GID)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- every process resolves names through these files
		return fmt.Errorf("accounts: %w", err)
	}
	for _, f := range []struct {
		name, body string
		mode       os.FileMode
	}{
		{"passwd", passwd.String(), 0o644},
		{"group", group.String(), 0o644},
		{"shadow", shadow.String(), 0o600},
	} {
		if err := writeAtomic(filepath.Join(dir, f.name), f.body, f.mode); err != nil {
			return err
		}
	}
	return nil
}

// MakeHomes creates each login account's home under root: empty, mode 0755
// and, when running as root, owned by root, which StrictModes accepts.
func MakeHomes(s access.State, root string) error {
	for _, a := range Accounts(s) {
		if !strings.HasPrefix(a.Home, HomeRoot+"/") {
			continue
		}
		p := filepath.Join(root, strings.TrimPrefix(a.Home, HomeRoot+"/"))
		if err := os.MkdirAll(p, 0o755); err != nil { // #nosec G301 -- sshd needs the home searchable
			return fmt.Errorf("accounts: %w", err)
		}
		if err := os.Chmod(p, 0o755); err != nil { // #nosec G302 -- a home must be searchable by sshd
			return fmt.Errorf("accounts: %w", err)
		}
		if os.Geteuid() == 0 {
			if err := os.Chown(p, 0, 0); err != nil {
				return fmt.Errorf("accounts: %w", err)
			}
		}
	}
	return nil
}

func writeAtomic(path, body string, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), mode); err != nil {
		return fmt.Errorf("accounts: %w", err)
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return fmt.Errorf("accounts: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("accounts: %w", err)
	}
	return nil
}
