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
	if err := accounts.Render(s, dir); err != nil {
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
	for _, gone := range []string{"enrol:", "maint:"} {
		if strings.Contains(readFile(t, filepath.Join(dir, "passwd")), gone) {
			t.Fatalf("%s is rendered", gone)
		}
	}
	if n := strings.Count(readFile(t, filepath.Join(dir, "passwd")), ":0:0:"); n != 1 {
		t.Fatalf("%d uid 0 accounts; only root, which can't log in", n)
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

func TestMakeHomes(t *testing.T) {
	root := t.TempDir()
	if err := accounts.MakeHomes(stateWithAdmins("alice:owner"), root); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice"} {
		fi, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if !fi.IsDir() || fi.Mode().Perm() != 0o755 {
			t.Fatalf("%s: %v", name, fi.Mode())
		}
	}
	for _, gone := range []string{"enrol", "maint"} {
		if _, err := os.Stat(filepath.Join(root, gone)); !os.IsNotExist(err) {
			t.Fatalf("a %s home was made", gone)
		}
	}
}
