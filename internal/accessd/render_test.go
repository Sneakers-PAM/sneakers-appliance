// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package accessd_test

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"os/signal"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) // #nosec G304 -- a test file
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// accessd renders the accounts and sshd's files from every version of the
// store, so logins keep authenticating from them while it is down.
func TestAccountsAndSSHFilesFollowTheStore(t *testing.T) {
	b := newBox(t)
	if p := read(t, filepath.Join(b.run, "accounts", "passwd")); !strings.Contains(p, "alice:x:") || !strings.Contains(p, "bob:x:") {
		t.Fatalf("passwd:\n%s", p)
	}
	cfg := read(t, filepath.Join(b.run, "ssh", "sshd_config"))
	if !strings.Contains(cfg, "ListenAddress 192.0.2.10:22") || !strings.Contains(cfg, "ListenAddress [2001:db8::10]:22") || strings.Contains(cfg, "fe80") {
		t.Fatalf("sshd_config:\n%s", cfg)
	}
	if !strings.Contains(cfg, "AllowUsers alice bob maint") {
		t.Fatalf("sshd_config:\n%s", cfg)
	}
	if k := read(t, filepath.Join(b.run, "ssh", "authorized_keys", "bob")); !strings.Contains(k, b.keys["bob"].line) {
		t.Fatalf("bob's keys:\n%s", k)
	}
	if err := b.store.Update(func(st *access.State) error {
		st.Admins = slices.DeleteFunc(st.Admins, func(a access.Admin) bool { return a.Name == "bob" })
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.run, "ssh", "authorized_keys", "bob")); !os.IsNotExist(err) {
		t.Fatalf("bob's keys are still there: %v", err)
	}
	if p := read(t, filepath.Join(b.run, "accounts", "passwd")); strings.Contains(p, "bob:x:") {
		t.Fatalf("passwd:\n%s", p)
	}
	if _, err := os.Stat(filepath.Join(b.run, "home", "alice")); err != nil {
		t.Fatal(err)
	}
}

// sshd re-reads its config on SIGHUP: accessd sends one when sshd_config
// changed (a new admin), not when only a key file did.
func TestSSHDIsToldWhenItsConfigChanges(t *testing.T) {
	b := newBox(t)
	hup := make(chan os.Signal, 4)
	signal.Notify(hup, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(hup) })
	if err := os.WriteFile(filepath.Join(b.run, "sshd.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b.addAdmin("carol", access.RoleAdmin)
	select {
	case <-hup:
	case <-time.After(3 * time.Second):
		t.Fatal("no SIGHUP after a new admin")
	}
	k := newKey(t)
	pk, err := access.ParseLoginKey(k.line)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.store.Update(func(st *access.State) error {
		a, _ := st.Admin("carol")
		a.Keys = append(a.Keys, access.AdminKey{Key: pk, Added: time.Now(), AddedBy: "carol", Via: access.ViaShell})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-hup:
		t.Fatal("SIGHUP for a key change")
	case <-time.After(300 * time.Millisecond):
	}
	if k2 := read(t, filepath.Join(b.run, "ssh", "authorized_keys", "carol")); !strings.Contains(k2, k.line) {
		t.Fatalf("carol's keys:\n%s", k2)
	}
}
