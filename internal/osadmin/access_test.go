// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
)

func TestRoles(t *testing.T) {
	b := newBox(t, true)
	bob := b.browser()
	bob.signIn("bob")
	ctx := context.Background()
	k := newKey(t)
	_, err := bob.access().AddAdmin(ctx, connect.NewRequest(&osadminv1.AddAdminRequest{Name: "carol", Role: osadminv1.Role_ROLE_ADMIN}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	_, err = bob.access().AddKey(ctx, connect.NewRequest(&osadminv1.AddKeyRequest{Admin: "alice", PublicKey: k.line}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	if _, err := bob.access().AddKey(ctx, connect.NewRequest(&osadminv1.AddKeyRequest{Admin: "bob", PublicKey: k.line})); err != nil {
		t.Fatalf("an admin manages their own keys: %v", err)
	}
	_, err = bob.access().SetRole(ctx, connect.NewRequest(&osadminv1.SetRoleRequest{Name: "bob", Role: osadminv1.Role_ROLE_OWNER}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")

	alice := b.browser()
	alice.signIn("alice")
	if _, err := alice.access().AddAdmin(ctx, connect.NewRequest(&osadminv1.AddAdminRequest{Name: "carol", Role: osadminv1.Role_ROLE_ADMIN, PublicKey: newKey(t).line})); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.access().SetRole(ctx, connect.NewRequest(&osadminv1.SetRoleRequest{Name: "bob", Role: osadminv1.Role_ROLE_OWNER})); err != nil {
		t.Fatal(err)
	}
	list, err := bob.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	if err != nil || len(list.Msg.GetAdmins()) != 3 {
		t.Fatalf("%v %v", list, err)
	}
	// A promotion applies to the live session at once.
	if _, err := bob.access().AddAdmin(ctx, connect.NewRequest(&osadminv1.AddAdminRequest{Name: "dave", Role: osadminv1.Role_ROLE_ADMIN})); err != nil {
		t.Fatalf("bob is an owner now: %v", err)
	}
}

func TestTheLastOwnerStays(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	_, err := alice.access().SetRole(ctx, connect.NewRequest(&osadminv1.SetRoleRequest{Name: "alice", Role: osadminv1.Role_ROLE_ADMIN}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ACCESS_LAST_OWNER")
	_, err = alice.access().RemoveAdmin(ctx, connect.NewRequest(&osadminv1.RemoveAdminRequest{Name: "alice"}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ACCESS_LAST_OWNER")
	_, err = alice.access().RemoveKey(ctx, connect.NewRequest(&osadminv1.RemoveKeyRequest{Admin: "alice", Fingerprint: b.keys["alice"].fp}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "ACCESS_LAST_KEY")
}

func TestRemovingAKeyOrAnAdminEndsTheirSessions(t *testing.T) {
	b := newBox(t, true)
	ctx := context.Background()
	alice := b.browser()
	alice.signIn("alice")
	second := newKey(t)
	if _, err := alice.access().AddKey(ctx, connect.NewRequest(&osadminv1.AddKeyRequest{Admin: "bob", PublicKey: second.line})); err != nil {
		t.Fatal(err)
	}
	bob1 := b.browser()
	bob1.signIn("bob")
	b.keys["bob-first"] = b.keys["bob"]
	b.keys["bob"] = second
	bob2 := b.browser()
	bob2.signIn("bob")

	if _, err := alice.access().RemoveKey(ctx, connect.NewRequest(&osadminv1.RemoveKeyRequest{Admin: "bob", Fingerprint: second.fp})); err != nil {
		t.Fatal(err)
	}
	_, err := bob2.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
	if _, err := bob1.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{})); err != nil {
		t.Fatalf("the other key's session stays: %v", err)
	}
	if _, err := alice.access().RemoveAdmin(ctx, connect.NewRequest(&osadminv1.RemoveAdminRequest{Name: "bob"})); err != nil {
		t.Fatal(err)
	}
	_, err = bob1.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
}

func TestHostKeysAndPolicy(t *testing.T) {
	b := newBox(t, false)
	dir := filepath.Join(b.state, "ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	hk := newKey(t)
	if err := os.WriteFile(filepath.Join(dir, "ssh_host_ed25519_key.pub"), []byte(hk.line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	if _, err := alice.access().SetElevationPolicy(ctx, connect.NewRequest(&osadminv1.SetElevationPolicyRequest{Policy: &osadminv1.ElevationPolicy{MaxMinutes: 120, DefaultMinutes: 30}})); err != nil {
		t.Fatal(err)
	}
	_, err := alice.access().SetElevationPolicy(ctx, connect.NewRequest(&osadminv1.SetElevationPolicyRequest{Policy: &osadminv1.ElevationPolicy{MaxMinutes: 500, DefaultMinutes: 30}}))
	if err == nil {
		t.Fatal("over 240 minutes")
	}
	l, err := alice.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Msg.GetHostKeys()) != 1 || l.Msg.GetHostKeys()[0].GetFingerprint() != hk.fp {
		t.Fatalf("host keys %v", l.Msg.GetHostKeys())
	}
	if l.Msg.GetElevationPolicy().GetMaxMinutes() != 120 {
		t.Fatal("policy")
	}
}
