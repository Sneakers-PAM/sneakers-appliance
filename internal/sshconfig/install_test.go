// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package sshconfig_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/sshconfig"
)

func installInput(t *testing.T, dir string, addrsIn ...string) sshconfig.Input {
	t.Helper()
	p := sshconfig.DefaultPaths()
	p.ConfigDir = filepath.Join(dir, "ssh")
	return sshconfig.Input{ListenAddrs: addrs(addrsIn...), State: twoAdmins(t), Paths: p}
}

func TestInstallSwapsInACheckedRender(t *testing.T) {
	dir := t.TempDir()
	checked := 0
	check := func(d string) error { checked++; return nil }
	in := installInput(t, dir, "192.0.2.10")
	changed, err := sshconfig.Install(in, check)
	mustNoErr(t, err)
	if !changed || checked != 1 {
		t.Fatalf("first install: changed %v, checked %d", changed, checked)
	}
	cfg, err := os.ReadFile(filepath.Join(dir, "ssh", "sshd_config"))
	mustNoErr(t, err)
	if !strings.Contains(string(cfg), "ListenAddress 192.0.2.10:22") {
		t.Fatalf("sshd_config:\n%s", cfg)
	}
	if changed, err := sshconfig.Install(in, check); err != nil || changed {
		t.Fatalf("same render: changed %v, %v", changed, err)
	}
	if changed, err := sshconfig.Install(installInput(t, dir, "192.0.2.11"), check); err != nil || !changed {
		t.Fatalf("new address: changed %v, %v", changed, err)
	}
	for _, left := range []string{"ssh.next", "ssh.old"} {
		if _, err := os.Stat(filepath.Join(dir, left)); !os.IsNotExist(err) {
			t.Fatalf("%s left behind: %v", left, err)
		}
	}
}

// sshd -t refusing a render leaves the live directory as it was.
func TestInstallKeepsTheOldConfigWhenSshdRefuses(t *testing.T) {
	dir := t.TempDir()
	_, err := sshconfig.Install(installInput(t, dir, "192.0.2.10"), func(string) error { return nil })
	mustNoErr(t, err)
	before, _ := os.ReadFile(filepath.Join(dir, "ssh", "sshd_config"))
	_, err = sshconfig.Install(installInput(t, dir, "192.0.2.11"), func(string) error { return errors.New("sshd -t: bad") })
	if err == nil {
		t.Fatal("a refused render was installed")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "ssh", "sshd_config"))
	if string(before) != string(after) {
		t.Fatalf("the live config changed:\n%s", after)
	}
}

func TestPortOverridesTheListenPort(t *testing.T) {
	dir := t.TempDir()
	in := installInput(t, dir, "192.0.2.10", "2001:db8::10")
	in.Port = 2222
	mustNoErr(t, sshconfig.Render(in, dir))
	cfg, _ := os.ReadFile(filepath.Join(dir, "sshd_config"))
	if !strings.Contains(string(cfg), "ListenAddress 192.0.2.10:2222") || !strings.Contains(string(cfg), "ListenAddress [2001:db8::10]:2222") {
		t.Fatalf("sshd_config:\n%s", cfg)
	}
}
