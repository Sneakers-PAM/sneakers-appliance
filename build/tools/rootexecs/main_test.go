// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func write(t *testing.T, p, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// The paths come from the code (not its tests) and the service tables, and
// each must be an executable file in the tree, through links; a link into
// /var is the running box's and isn't checked.
func TestEveryExecdPathIsInTheTree(t *testing.T) {
	src, tree := t.TempDir(), t.TempDir()
	write(t, filepath.Join(src, "internal", "luks", "luks.go"), `package luks
const cryptsetup = "/usr/sbin/cryptsetup"
var mkfs = "/usr/sbin/mkfs.ext4"`, 0o644)
	write(t, filepath.Join(src, "internal", "luks", "luks_test.go"), `package luks
const fake = "/usr/bin/only-in-a-test"`, 0o644)
	write(t, filepath.Join(src, "cmd", "x", "main.go"), `package main
const ssh = "/usr/libexec/openssh/sshd-session"
const state = "/var/lib/sneakers/thing"
const kubectl = "/usr/bin/kubectl"`, 0o644)
	services := filepath.Join(src, "services.d")
	write(t, filepath.Join(services, "k0s.yaml"), "exec: /bin/sh\nargs: [/usr/libexec/sneakers/k0s-interim, run]\npre-start: [/usr/bin/sneakers-edgefall, prepare]\n", 0o644)

	paths, err := execd(src, []string{services})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/bin/sh", "/usr/bin/kubectl", "/usr/bin/sneakers-edgefall", "/usr/libexec/openssh/sshd-session", "/usr/libexec/sneakers/k0s-interim", "/usr/sbin/cryptsetup", "/usr/sbin/mkfs.ext4"}
	if !slices.Equal(paths, want) {
		t.Fatalf("paths %v", paths)
	}

	for _, p := range []string{"bin/busybox", "usr/bin/sneakers-edgefall", "usr/libexec/openssh/sshd-session", "usr/libexec/sneakers/k0s-interim", "usr/sbin/cryptsetup"} {
		write(t, filepath.Join(tree, p), "x", 0o755)
	}
	if err := os.Symlink("busybox", filepath.Join(tree, "bin", "sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/var/lib/sneakers/product/current/k0s", filepath.Join(tree, "usr", "bin", "kubectl")); err != nil {
		t.Fatal(err)
	}
	missing := check(tree, paths)
	if len(missing) != 1 || !strings.HasPrefix(missing[0], "/usr/sbin/mkfs.ext4 ") {
		t.Fatalf("missing %v", missing)
	}
	write(t, filepath.Join(tree, "usr", "sbin", "mkfs.ext4"), "x", 0o644)
	if missing := check(tree, paths); len(missing) != 1 || !strings.Contains(missing[0], "mkfs.ext4") {
		t.Fatalf("a file that isn't executable passed: %v", missing)
	}
}

// The real tree's code and service tables name the binaries first boot
// can't do without.
func TestTheRepositorysListHasTheFirstBootTools(t *testing.T) {
	paths, err := execd(filepath.Join("..", "..", ".."), []string{filepath.Join("..", "..", "..", "os", "rootfs", "services.d")})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/usr/sbin/cryptsetup", "/usr/sbin/mkfs.ext4", "/usr/sbin/veritysetup", "/usr/bin/sneakers-accessd", "/sbin/init"} {
		if !slices.Contains(paths, p) {
			t.Errorf("%s isn't among the exec'd paths %v", p, paths)
		}
	}
}
