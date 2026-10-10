// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package k0s_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
)

// The box's own copy of the CNI plugins, which containerd runs.
const cniPluginCopy = "/var/lib/sneakers/k0s/cni-bin"

// cniPlugins runs k0s-interim's cni_plugins from src into dst.
func cniPlugins(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile("k0s-interim")
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?ms)^cni_plugins\(\) \{\n.*?^\}\n`).Find(b)
	if fn == nil {
		t.Fatal("k0s-interim has no cni_plugins function")
	}
	script := "set -eu\n" + string(fn) + `cni_plugins "$1" "$2"` + "\n"
	if out, err := exec.Command("sh", "-c", script, "sh", src, dst).CombinedOutput(); err != nil { // #nosec G204 -- the repo's own script
		t.Fatalf("cni_plugins: %v: %s", err, out)
	}
}

func inode(t *testing.T, p string) uint64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// writeInPlace rewrites p the way cni-node's busybox install does: the
// same inode, opened with O_TRUNC.
func writeInPlace(t *testing.T, p, content string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755) // #nosec G302 G304 -- a test plugin
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// kube-router's install-cni-bins rewrites every plugin in /opt/cni/bin in
// place at each start of its pod, and after a reboot containerd already
// runs them for the other pods' sandboxes: an exec while a plugin is open
// for writing fails with ETXTBSY, and libcni's retry of it fails with
// "exec: already started". containerd runs the box's own copy instead,
// which nothing writes while k0s runs.
func TestTheCNIPluginCopyIsntTheInstallersFile(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "opt-cni-bin"), filepath.Join(dir, "cni-bin")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}

	// A first boot: the installer hasn't run yet.
	cniPlugins(t, src, dst)
	if left, _ := os.ReadDir(dst); len(left) != 0 {
		t.Fatalf("with no plugins installed the copy holds %d files", len(left))
	}

	writeInPlace(t, filepath.Join(src, "bridge"), "bridge 1")
	writeInPlace(t, filepath.Join(src, "loopback"), "loopback 1")
	cniPlugins(t, src, dst)
	for name, want := range map[string]string{"bridge": "bridge 1", "loopback": "loopback 1"} {
		p := filepath.Join(dst, name)
		got, err := os.ReadFile(p) // #nosec G304 -- the test's own file
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%s holds %q; want %q", name, got, want)
		}
		if fi, _ := os.Stat(p); fi.Mode().Perm()&0o100 == 0 {
			t.Errorf("%s isn't executable: %v", name, fi.Mode())
		}
		if inode(t, p) == inode(t, filepath.Join(src, name)) {
			t.Errorf("%s is the installer's own file", name)
		}
	}
	loopback := inode(t, filepath.Join(dst, "loopback"))
	bridge := inode(t, filepath.Join(dst, "bridge"))

	// The installer runs while k0s does: the copy containerd runs stays.
	writeInPlace(t, filepath.Join(src, "bridge"), "bridge 2")
	if got, _ := os.ReadFile(filepath.Join(dst, "bridge")); string(got) != "bridge 1" { // #nosec G304 -- the test's own file
		t.Fatalf("rewriting the installed bridge changed the copy to %q", got)
	}

	// The next k0s start takes the new plugin, as a new file (an exec of
	// the old one, if any, keeps its inode), and leaves the same one alone.
	cniPlugins(t, src, dst)
	if got, _ := os.ReadFile(filepath.Join(dst, "bridge")); string(got) != "bridge 2" { // #nosec G304 -- the test's own file
		t.Errorf("the next start left bridge at %q", got)
	}
	if inode(t, filepath.Join(dst, "bridge")) == bridge {
		t.Error("the new bridge was written into the old file, not renamed in")
	}
	if inode(t, filepath.Join(dst, "loopback")) != loopback {
		t.Error("an unchanged plugin was copied again")
	}
	if left, _ := filepath.Glob(filepath.Join(dst, "*.new")); len(left) != 0 {
		t.Errorf("left behind %v", left)
	}
}

// containerd looks in the box's copy first and in /opt/cni/bin after it,
// for a first boot, before the copy holds anything; the CNI config isn't
// there then until the installer has finished. k0s-interim makes the copy
// at every start, before k0s.
func TestContainerdRunsTheBoxsCopyOfTheCNIPlugins(t *testing.T) {
	b, err := os.ReadFile("containerd.toml")
	if err != nil {
		t.Fatal(err)
	}
	section := regexp.MustCompile(`(?ms)^\[plugins\."io\.containerd\.cri\.v1\.runtime"\.cni\]\n(.*?)(?:^\[|\z)`).FindSubmatch(b)
	if section == nil {
		t.Fatal(`containerd.toml has no [plugins."io.containerd.cri.v1.runtime".cni] section`)
	}
	want := `bin_dirs = ["` + cniPluginCopy + `", "/opt/cni/bin"]`
	if !strings.Contains(string(section[1]), want) {
		t.Errorf("containerd's CNI section doesn't have %s:\n%s", want, section[1])
	}
	if strings.Contains(string(section[1]), "bin_dir =") {
		t.Error("containerd's CNI section sets bin_dir too; containerd refuses both")
	}

	s, err := os.ReadFile("k0s-interim")
	if err != nil {
		t.Fatal(err)
	}
	if call := "cni_plugins /var/lib/opt/cni/bin " + cniPluginCopy; !strings.Contains(string(s), call) {
		t.Errorf("k0s-interim doesn't run %q", call)
	}
}
