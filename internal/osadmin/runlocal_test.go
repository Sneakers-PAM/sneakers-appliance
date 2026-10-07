// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

func addAdminLocal(b *box, l osadmin.Local, name string) error {
	h := b.srv.Handlers()
	return b.srv.RunLocal(context.Background(), l, osadminv1connect.AccessServiceAddAdminProcedure, func(ctx context.Context) error {
		_, err := h.Access.AddAdmin(ctx, connect.NewRequest(&osadminv1.AddAdminRequest{Name: name, Role: osadminv1.Role_ROLE_ADMIN}))
		return err
	})
}

// A closed-shell login acts as its admin, with that admin's role, and
// every call is audited from the ssh surface.
func TestRunLocalUsesTheAdminsRole(t *testing.T) {
	b := newBox(t, true)
	err := addAdminLocal(b, osadmin.Local{Admin: "bob", KeyFP: b.keys["bob"].fp, Source: "192.0.2.5"}, "carol")
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	if e := lastEntry(t, b.log, "access.admin.add"); e.Actor != "bob" || e.Outcome != "refused" || e.Detail["surface"] != osadmin.SurfaceSSH || e.Source != "192.0.2.5" {
		t.Fatalf("%+v", e)
	}
	if err := addAdminLocal(b, osadmin.Local{Admin: "alice", KeyFP: b.keys["alice"].fp}, "carol"); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, b.log, "access.admin.add"); e.Actor != "alice" || e.Outcome != "ok" || e.KeyFP != b.keys["alice"].fp {
		t.Fatalf("%+v", e)
	}
	st := b.store.Read()
	if a, ok := st.Admin("carol"); !ok || a.CreatedBy != "alice" {
		t.Fatalf("%+v %v", a, ok)
	}
}

// The console (root) acts as an owner named console.
func TestRunLocalConsoleIsAnOwner(t *testing.T) {
	b := newBox(t, false)
	if err := addAdminLocal(b, osadmin.Local{}, "carol"); err != nil {
		t.Fatal(err)
	}
	if e := lastEntry(t, b.log, "access.admin.add"); e.Actor != "console" || e.Detail["surface"] != "console" {
		t.Fatalf("%+v", e)
	}
}

// A fingerprint that isn't the admin's, or an admin that's gone, is
// refused before the handler runs.
func TestRunLocalChecksTheAdminAndKey(t *testing.T) {
	b := newBox(t, true)
	err := addAdminLocal(b, osadmin.Local{Admin: "alice", KeyFP: b.keys["bob"].fp}, "carol")
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	err = addAdminLocal(b, osadmin.Local{Admin: "mallory"}, "carol")
	symbolIn(t, err, connect.CodeUnauthenticated, "ACCESS_SESSION")
	st := b.store.Read()
	if _, ok := st.Admin("carol"); ok {
		t.Fatal("a refused call ran")
	}
	err = b.srv.RunLocal(context.Background(), osadmin.Local{}, "/no.such.Service/Method", func(context.Context) error { return nil })
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("a procedure with no rule ran: %v", err)
	}
}
