// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/access"
)

// revokedFPs lists the fingerprints a state holds as revoked.
func revokedFPs(st access.State) []string {
	var out []string
	for _, r := range st.RevokedKeys {
		out = append(out, r.Fingerprint)
	}
	return out
}

func TestRemovingAKeyRevokesItInTheSameWrite(t *testing.T) {
	st, _ := openStoreWithOwnerTwoKeys(t)
	cur := st.Read()
	a, _ := cur.Admin("alice")
	gone := a.Keys[1]
	if err := st.Update(removeKey(1)); err != nil {
		t.Fatal(err)
	}
	got := st.Read()
	if !slices.Equal(revokedFPs(got), []string{gone.Fingerprint}) {
		t.Fatalf("revoked %v, want %s", revokedFPs(got), gone.Fingerprint)
	}
	r := got.RevokedKeys[0]
	if r.Admin != "alice" || r.PublicKey != gone.PublicKey || r.Revoked.IsZero() {
		t.Fatalf("%+v", r)
	}
}

func TestRemovingAnAdminRevokesEveryKey(t *testing.T) {
	st, _ := openStoreWithOwnerTwoKeys(t)
	bk1, bk2 := loginKey(t), loginKey(t)
	if err := st.Update(func(s *access.State) error {
		b := s.AddAdmin("bob", access.RoleAdmin, "alice", t0)
		b.Keys = append(b.Keys, bk1, bk2)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(func(s *access.State) error {
		s.Admins = slices.DeleteFunc(s.Admins, func(a access.Admin) bool { return a.Name == "bob" })
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got := revokedFPs(st.Read())
	if len(got) != 2 || !slices.Contains(got, bk1.Fingerprint) || !slices.Contains(got, bk2.Fingerprint) {
		t.Fatalf("revoked %v", got)
	}
}

func TestARevokedKeyCantBeAddedAgain(t *testing.T) {
	st, _ := openStoreWithOwnerTwoKeys(t)
	cur := st.Read()
	a, _ := cur.Admin("alice")
	gone := a.Keys[1]
	if err := st.Update(removeKey(1)); err != nil {
		t.Fatal(err)
	}
	readd := func(s *access.State) error {
		a, _ := s.Admin("alice")
		a.Keys = append(a.Keys, gone)
		return nil
	}
	assertCode(t, st.Update(readd), "ACCESS_KEY_REVOKED")
	// Not for another admin either.
	assertCode(t, st.Update(func(s *access.State) error {
		b := s.AddAdmin("bob", access.RoleAdmin, "alice", t0)
		b.Keys = append(b.Keys, gone)
		return nil
	}), "ACCESS_KEY_REVOKED")

	if err := st.Update(func(s *access.State) error {
		if !s.Unrevoke(gone.Fingerprint) {
			return errors.New("not revoked")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(readd); err != nil {
		t.Fatalf("an un-revoked key is refused: %v", err)
	}
}

// The revocation list is written inside the store's write: a change whose
// list can't be written doesn't happen, so a key is never gone from the
// store and still accepted by sshd.
func TestTheRevokeHookRunsBeforeTheWriteAndCanRefuseIt(t *testing.T) {
	dir := t.TempDir()
	var seen [][]string
	fail := false
	st, err := access.Open(dir, access.Options{Revoke: func(s access.State) error {
		seen = append(seen, revokedFPs(s))
		if fail {
			return errors.New("disk full")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || len(seen[0]) != 0 {
		t.Fatalf("Open didn't write the list from the stored state: %v", seen)
	}
	k1, k2 := loginKey(t), loginKey(t)
	if err := st.Update(func(s *access.State) error {
		a := signIn(s.AddAdmin("alice", access.RoleOwner, "setup", t0))
		a.Keys = append(a.Keys, k1, k2)
		s.RecoveryKeys = recoveryKeys(t, 1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := st.Update(removeKey(1)); err == nil {
		t.Fatal("a change whose revocation list failed was written")
	}
	after := st.Read()
	if a, _ := after.Admin("alice"); len(a.Keys) != 2 {
		t.Fatalf("the key left the store: %d keys", len(a.Keys))
	}
	fail = false
	if err := st.Update(removeKey(1)); err != nil {
		t.Fatal(err)
	}
	last := seen[len(seen)-1]
	if !slices.Equal(last, []string{k2.Fingerprint}) {
		t.Fatalf("the hook saw %v", last)
	}
}

func TestRevokedPublicKeysParse(t *testing.T) {
	st, _ := openStoreWithOwnerTwoKeys(t)
	if err := st.Update(removeKey(0)); err != nil {
		t.Fatal(err)
	}
	keys, err := st.Read().RevokedPublicKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("%d keys", len(keys))
	}
}

func TestARevocationRecordsWhoRemovedTheKey(t *testing.T) {
	st, _ := openStoreWithOwnerTwoKeys(t)
	if err := st.UpdateAs("carol", removeKey(1)); err != nil {
		t.Fatal(err)
	}
	got := st.Read().RevokedKeys
	if len(got) != 1 || got[0].RevokedBy != "carol" || got[0].By() != "carol" {
		t.Fatalf("%+v", got)
	}
}

func TestAnAdminsRemovalRecordsWhoRemovedThem(t *testing.T) {
	st, _ := openStoreWithOwnerTwoKeys(t)
	if err := st.Update(func(s *access.State) error {
		b := s.AddAdmin("bob", access.RoleAdmin, "alice", t0)
		b.Keys = append(b.Keys, loginKey(t), loginKey(t))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateAs(access.ConsoleActor, func(s *access.State) error {
		s.Admins = slices.DeleteFunc(s.Admins, func(a access.Admin) bool { return a.Name == "bob" })
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, r := range st.Read().RevokedKeys {
		if r.By() != access.ConsoleActor {
			t.Fatalf("%+v", r)
		}
	}
}

// A store written before revocations named their actor reads cleanly, and
// its revocations are by "unknown".
func TestARevocationFromAnOlderStoreIsByUnknown(t *testing.T) {
	st, dir := openStoreWithOwnerTwoKeys(t)
	if err := st.Update(removeKey(1)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, access.FileName)
	b, err := os.ReadFile(p) // #nosec G304 -- the test's own store
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "revokedBy") {
		t.Fatalf("a revocation with no actor wrote one:\n%s", b)
	}
	old, err := access.ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(old.RevokedKeys) != 1 || old.RevokedKeys[0].By() != access.UnknownActor {
		t.Fatalf("%+v", old.RevokedKeys)
	}
	if _, err := access.Open(dir, access.Options{}); err != nil {
		t.Fatalf("the older store doesn't open: %v", err)
	}
}
