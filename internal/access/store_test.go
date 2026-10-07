// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
)

func openStoreWithOwnerTwoKeys(t *testing.T) (*access.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := access.Open(dir, access.Options{})
	if err != nil {
		t.Fatal(err)
	}
	k1, k2 := loginKey(t), loginKey(t)
	rk := recoveryKeys(t, 1)
	err = st.Update(func(s *access.State) error {
		a := s.AddAdmin("alice", access.RoleOwner, "console", t0)
		a.Keys = append(a.Keys, k1, k2)
		s.RecoveryKeys = rk
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return st, dir
}

func removeKey(i int) func(*access.State) error {
	return func(s *access.State) error {
		a, _ := s.Admin("alice")
		// Each writer removes "its" key by position in the list it read.
		fp := []string{}
		for _, k := range a.Keys {
			fp = append(fp, k.Fingerprint)
		}
		if i >= len(fp) {
			a.Keys = nil
			return nil
		}
		kept := a.Keys[:0]
		for _, k := range a.Keys {
			if k.Fingerprint != fp[i] {
				kept = append(kept, k)
			}
		}
		a.Keys = kept
		return nil
	}
}

func TestConcurrentUpdatesKeepInvariants(t *testing.T) {
	st, _ := openStoreWithOwnerTwoKeys(t)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = st.Update(removeKey(i)) }()
	}
	wg.Wait()
	if errs[0] == nil && errs[1] == nil {
		t.Fatal("both removals succeeded; the last key is gone")
	}
	failed := errs[0]
	if failed == nil {
		failed = errs[1]
	}
	assertCode(t, failed, "ACCESS_LAST_KEY")
	assertCode(t, access.Check(st.Read(), true, true), "")
}

func TestUpdatePersistsAndVersions(t *testing.T) {
	st, dir := openStoreWithOwnerTwoKeys(t)
	if v := st.Read().Version; v != 1 {
		t.Fatalf("version %d after one write", v)
	}
	again, err := access.Open(dir, access.Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := again.Read()
	if got.Version != 1 || len(got.Admins) != 1 || len(got.Admins[0].Keys) != 2 || got.Admins[0].UID != access.FirstUID || got.NextUID != access.FirstUID+1 {
		t.Fatalf("reopened %+v", got)
	}
	fi, err := os.Stat(filepath.Join(dir, access.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("store mode %v", fi.Mode().Perm())
	}
}

func TestRefusedUpdateChangesNothing(t *testing.T) {
	st, dir := openStoreWithOwnerTwoKeys(t)
	before, _ := os.ReadFile(filepath.Join(dir, access.FileName))
	assertCode(t, st.Update(func(s *access.State) error { s.Admins[0].Keys = nil; return nil }), "ACCESS_LAST_KEY")
	boom := errors.New("caller refused")
	if err := st.Update(func(*access.State) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("fn error not returned: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, access.FileName))
	if string(before) != string(after) || st.Read().Version != 1 {
		t.Fatal("a refused change was written")
	}
}

func TestUIDsAreNeverReused(t *testing.T) {
	st, _ := openStoreWithOwnerTwoKeys(t)
	add := func(name string) {
		k := loginKey(t)
		if err := st.Update(func(s *access.State) error {
			s.AddAdmin(name, access.RoleAdmin, "alice", t0).Keys = []access.AdminKey{k}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	add("bob")
	if err := st.Update(func(s *access.State) error { s.Admins = s.Admins[:1]; return nil }); err != nil {
		t.Fatal(err)
	}
	add("carol")
	s := st.Read()
	carol, _ := s.Admin("carol")
	if carol.UID != access.FirstUID+2 {
		t.Fatalf("carol got uid %d; bob's %d was reused", carol.UID, access.FirstUID+1)
	}
}

func TestCrashBeforeRenameKeepsPreviousVersion(t *testing.T) {
	_, dir := openStoreWithOwnerTwoKeys(t)
	// A write that died before its rename: a truncated tmp file.
	if err := os.WriteFile(filepath.Join(dir, access.FileName+".tmp"), []byte(`{"version": 2, "adm`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := access.Open(dir, access.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if v := st.Read().Version; v != 1 {
		t.Fatalf("version %d, want the previous 1", v)
	}
	if _, err := os.Stat(filepath.Join(dir, access.FileName+".tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the stale tmp file was left")
	}
}

func TestCorruptStoreIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, access.FileName), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := access.Open(dir, access.Options{})
	assertCode(t, err, "ACCESS_STORE_INVALID")
}

func TestStageRelaxesSetupInvariants(t *testing.T) {
	st, err := access.Open(t.TempDir(), access.Options{Stage: func() (bool, bool) { return false, false }})
	if err != nil {
		t.Fatal(err)
	}
	// Step 3 not done: an owner with no key yet is allowed.
	assertCode(t, st.Update(func(s *access.State) error { s.AddAdmin("alice", access.RoleOwner, "console", t0); return nil }), "")
}

func TestStoreShape(t *testing.T) {
	_, dir := openStoreWithOwnerTwoKeys(t)
	b, err := os.ReadFile(filepath.Join(dir, access.FileName))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "admins", "recoveryKeys", "elevationPolicy"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("store.json has no %q", k)
		}
	}
	admin := raw["admins"].([]any)[0].(map[string]any)
	key := admin["keys"].([]any)[0].(map[string]any)
	for _, k := range []string{"fingerprint", "type", "publicKey", "added", "addedBy", "via"} {
		if _, ok := key[k]; !ok {
			t.Errorf("key has no %q", k)
		}
	}
	if _, ok := admin["approvalHoldUntil"]; !ok {
		t.Error("admin has no approvalHoldUntil")
	}
}

func TestReadStateSeesTheWritersLatestVersion(t *testing.T) {
	dir := t.TempDir()
	s, err := access.Open(dir, access.Options{Stage: func() (bool, bool) { return true, false }})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(st *access.State) error {
		a := st.AddAdmin("alice", access.RoleOwner, "test", time.Now())
		a.Keys = append(a.Keys, loginKey(t))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st, err := access.ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Admin("alice"); !ok || st.Version != s.Read().Version {
		t.Fatalf("%+v", st)
	}
	if _, err := os.Stat(filepath.Join(dir, access.FileName+".tmp")); err == nil {
		t.Fatal("reading left a file behind")
	}
}
