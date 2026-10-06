// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accounts_test

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/accounts"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func stateWithAdmins(specs ...string) access.State {
	s := access.State{NextUID: access.FirstUID}
	for _, spec := range specs {
		name, role, _ := strings.Cut(spec, ":")
		s.AddAdmin(name, access.Role(role), "console", time.Date(2026, 10, 5, 14, 0, 0, 0, time.UTC))
	}
	return s
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func golden(t *testing.T, got, want string) {
	t.Helper()
	if *update {
		if err := os.WriteFile(want, []byte(readFile(t, got)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if g, w := readFile(t, got), readFile(t, want); g != w {
		t.Fatalf("%s differs from %s:\n%s", got, want, g)
	}
}

func TestRender(t *testing.T) {
	dir := t.TempDir()
	s := stateWithAdmins("alice:owner", "bob:admin")
	if err := accounts.Render(s, false, dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"passwd", "group", "shadow"} {
		golden(t, filepath.Join(dir, f), "testdata/"+f+".golden")
	}
	for _, line := range strings.Split(strings.TrimSpace(readFile(t, filepath.Join(dir, "passwd"))), "\n") {
		if n := strings.Count(line, ":"); n != 6 {
			t.Fatalf("passwd line has %d separators: %q", n, line)
		}
	}
	shadow := readFile(t, filepath.Join(dir, "shadow"))
	for _, line := range strings.Split(strings.TrimSpace(shadow), "\n") {
		if strings.Split(line, ":")[1] != "*" {
			t.Fatalf("account has a password field: %q", line)
		}
	}
	if strings.Contains(readFile(t, filepath.Join(dir, "passwd")), "enrol:") {
		t.Fatal("enrol rendered outside the window")
	}
	for f, mode := range map[string]os.FileMode{"passwd": 0o644, "group": 0o644, "shadow": 0o600} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != mode {
			t.Errorf("%s mode %v, want %v", f, fi.Mode().Perm(), mode)
		}
	}
}

func TestRenderEnrolWindow(t *testing.T) {
	dir := t.TempDir()
	if err := accounts.Render(stateWithAdmins(), true, dir); err != nil {
		t.Fatal(err)
	}
	passwd := readFile(t, filepath.Join(dir, "passwd"))
	if !strings.Contains(passwd, "enrol:x:103:103:SSH key enrolment:/run/sneakers/home/enrol:/usr/libexec/sneakers-enrol\n") {
		t.Fatalf("no enrol account in the window:\n%s", passwd)
	}
	if !strings.Contains(readFile(t, filepath.Join(dir, "shadow")), "enrol:*:") {
		t.Fatal("no shadow entry for enrol")
	}
	// Closing the window takes the account away again.
	if err := accounts.Render(stateWithAdmins(), false, dir); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(readFile(t, filepath.Join(dir, "passwd")), "enrol:") {
		t.Fatal("enrol survived the window")
	}
	if _, err := os.Stat(filepath.Join(dir, "passwd.tmp")); !os.IsNotExist(err) {
		t.Fatal("a tmp file was left")
	}
}

func TestMakeHomes(t *testing.T) {
	root := t.TempDir()
	if err := accounts.MakeHomes(stateWithAdmins("alice:owner"), false, root); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "maint"} {
		fi, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if !fi.IsDir() || fi.Mode().Perm() != 0o755 {
			t.Fatalf("%s: %v", name, fi.Mode())
		}
	}
	if _, err := os.Stat(filepath.Join(root, "enrol")); !os.IsNotExist(err) {
		t.Fatal("enrol home made outside the window")
	}
}
