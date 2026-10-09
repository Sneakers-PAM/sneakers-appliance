// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

// While the product has no first admin, an admin reads its one-time setup
// token and the link; the same token every time, from the box's one
// store. Once the product says its first admin exists the token is
// consumed and removed, and every read is audited without the token.
func TestTheProductSetupToken(t *testing.T) {
	var setUp atomic.Bool
	var answering atomic.Bool
	b := newBox(t, false, func(_ *box, o *osadmin.Options) {
		o.ProductNeedsSetup = func(context.Context) (bool, error) {
			if !answering.Load() {
				return false, errors.New("the product isn't answering yet")
			}
			return !setUp.Load(), nil
		}
	})
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	read := func() *osadminv1.GetProductSetupTokenResponse {
		t.Helper()
		out, err := alice.upgrade().GetProductSetupToken(ctx, connect.NewRequest(&osadminv1.GetProductSetupTokenRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return out.Msg
	}
	if m := read(); m.GetProduct() != "" || m.GetToken() != "" || m.GetSetUp() {
		t.Fatalf("with no product %v", m)
	}
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}

	// The product is still starting: the token is given all the same.
	m := read()
	if m.GetProduct() != "Sneakers" || m.GetSetUp() || !strings.HasPrefix(m.GetToken(), "stp_") || m.GetSetupUrl() != "https://box1.sneakers.example.org/admin/setup" {
		t.Fatalf("before setup %v", m)
	}
	file, err := os.ReadFile(filepath.Join(b.state, "osadmin-api", "product-setup", "token"))
	if err != nil || strings.TrimSpace(string(file)) != m.GetToken() {
		t.Fatalf("the token isn't the store's: %v", err)
	}
	answering.Store(true)
	if again := read(); again.GetToken() != m.GetToken() {
		t.Fatal("a second read gave another token")
	}
	e := lastEntry(t, b.log, "product.setup-token.read")
	if e.Outcome != "ok" || e.Actor != "alice" {
		t.Fatalf("audit %+v", e)
	}
	es, err := b.log.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(es); strings.Contains(string(raw), m.GetToken()) {
		t.Fatal("the token is in the audit log")
	}

	setUp.Store(true)
	if done := read(); !done.GetSetUp() || done.GetToken() != "" {
		t.Fatalf("after setup %v", done)
	}
	if _, err := os.Stat(filepath.Join(b.state, "osadmin-api", "product-setup", "token")); !os.IsNotExist(err) {
		t.Fatal("the consumed token is still on disk")
	}
	setUp.Store(false)
	if done := read(); !done.GetSetUp() || done.GetToken() != "" {
		t.Fatalf("a consumed token came back %v", done)
	}
	if e := lastEntry(t, b.log, "product.setup-token.read"); e.Detail["state"] != "set-up" {
		t.Fatalf("audit %+v", e)
	}
}
