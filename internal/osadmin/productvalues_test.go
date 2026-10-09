// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
)

// fakeKube is the cluster as the appliance's service account sees it.
// It holds more than the bundle declares, so a test can tell the box
// reads only what's declared.
type fakeKube struct {
	mu      sync.Mutex
	secrets map[string]map[string]string
	state   string
	reads   []string
}

func (k *fakeKube) SecretKey(_ context.Context, ns, name, key string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.reads = append(k.reads, ns+"/"+name+"/"+key)
	v, ok := k.secrets[ns+"/"+name][key]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func (k *fakeKube) ServiceGet(_ context.Context, ns, proxy, path string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.reads = append(k.reads, "proxy "+ns+"/"+proxy+path)
	if k.state == "" {
		return nil, errors.New("the gateway isn't up")
	}
	return []byte(k.state), nil
}

const valuesYAML = `format: 2
exposed_values:
  - name: setup-token
    secret: sneakers/sneakers-setup-token
    key: SETUP_TOKEN
    roles: [owner, admin]
    one_time: true
    consumed_when: {service: "sneakers/sneakers-gateway:http", path: /setup/state, field: needsSetup, equals: false}
    label: Sneakers setup token
    link: "https://{host}/admin/setup"
  - name: owner-only
    secret: sneakers/sneakers-support
    key: SUPPORT_ID
    roles: [owner]
`

// installProduct puts a product slot with spec as its product.yaml in the
// box's product directory, as an installed bundle.
func installProduct(t *testing.T, dir, spec string) {
	t.Helper()
	slot := filepath.Join(dir, "a")
	if err := os.MkdirAll(slot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slot, "bundle.json"), []byte(`{"name":"sneakers-product","version":"0.1.0","kind":"product"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if spec != "" {
		if err := os.WriteFile(filepath.Join(slot, "product.yaml"), []byte(spec), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("a", filepath.Join(dir, "current")); err != nil {
		t.Fatal(err)
	}
}

func valuesBox(t *testing.T) (*box, *fakeKube) {
	t.Helper()
	k := &fakeKube{secrets: map[string]map[string]string{
		"sneakers/sneakers-setup-token": {"SETUP_TOKEN": "stp_value", "OTHER": "never"},
		"sneakers/sneakers-support":     {"SUPPORT_ID": "sup-1"},
		"sneakers/sneakers-db":          {"PASSWORD": "never"},
	}, state: `{"needsSetup": true}`}
	b := newBox(t, true, func(_ *box, o *osadmin.Options) { o.Exposed = k })
	installProduct(t, filepath.Join(b.state, "product"), valuesYAML)
	return b, k
}

func (br *browser) product() osadminv1connect.ProductServiceClient {
	return osadminv1connect.NewProductServiceClient(br.hc, br.b.ts.URL)
}

func TestAnExposedValueIsReadWithItsLinkUntilItsConsumed(t *testing.T) {
	b, k := valuesBox(t)
	ctx := context.Background()
	bob := b.browser()
	bob.signIn("bob")
	l, err := bob.product().ListExposedValues(ctx, connect.NewRequest(&osadminv1.ListExposedValuesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if l.Msg.GetProduct() != "sneakers" || len(l.Msg.GetValues()) != 1 || l.Msg.GetValues()[0].GetName() != "setup-token" {
		t.Fatalf("an admin's list %v", l.Msg)
	}
	g, err := bob.product().GetExposedValue(ctx, connect.NewRequest(&osadminv1.GetExposedValueRequest{Name: "setup-token"}))
	if err != nil {
		t.Fatal(err)
	}
	if g.Msg.GetValue() != "stp_value" || g.Msg.GetEntry().GetLink() != "https://box1.sneakers.example.org/admin/setup" || g.Msg.GetEntry().GetConsumed() {
		t.Fatalf("%v", g.Msg)
	}
	e := lastEntry(t, b.log, "product.value.read")
	if e.Outcome != "ok" || e.Actor != "bob" || e.Detail["name"] != "setup-token" || e.Detail["state"] != "shown" {
		t.Fatalf("audit %+v", e)
	}
	for _, v := range e.Detail {
		if strings.Contains(v, "stp_value") {
			t.Fatal("the value is in the audit")
		}
	}

	k.mu.Lock()
	k.state = `{"needsSetup": false}`
	k.mu.Unlock()
	g, err = bob.product().GetExposedValue(ctx, connect.NewRequest(&osadminv1.GetExposedValueRequest{Name: "setup-token"}))
	if err != nil || g.Msg.GetValue() != "" || !g.Msg.GetEntry().GetConsumed() {
		t.Fatalf("after setup %v %v", g, err)
	}
	// Consumed for good: even if the product said otherwise later, the
	// value never comes back.
	k.mu.Lock()
	k.state = `{"needsSetup": true}`
	k.mu.Unlock()
	g, err = bob.product().GetExposedValue(ctx, connect.NewRequest(&osadminv1.GetExposedValueRequest{Name: "setup-token"}))
	if err != nil || g.Msg.GetValue() != "" || !g.Msg.GetEntry().GetConsumed() {
		t.Fatalf("after it was consumed %v %v", g, err)
	}
	if e := lastEntry(t, b.log, "product.value.read"); e.Detail["state"] != "consumed" {
		t.Fatalf("audit %+v", e)
	}
}

// Only what the bundle declares can be read, by the roles it lists: an
// undeclared name (another key of a declared Secret, or another Secret) is
// refused for everyone, owners included, and the box never asks the
// cluster for it.
func TestAnUndeclaredValueIsRefusedEvenForAnOwner(t *testing.T) {
	b, k := valuesBox(t)
	ctx := context.Background()
	alice := b.browser()
	alice.signIn("alice")
	for _, name := range []string{"OTHER", "sneakers-db", "PASSWORD", "../setup-token", "setup-token/OTHER", ""} {
		_, err := alice.product().GetExposedValue(ctx, connect.NewRequest(&osadminv1.GetExposedValueRequest{Name: name}))
		symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
		if e := lastEntry(t, b.log, "product.value.read"); e.Outcome != "refused" {
			t.Fatalf("%q: audit %+v", name, e)
		}
	}
	bob := b.browser()
	bob.signIn("bob")
	_, err := bob.product().GetExposedValue(ctx, connect.NewRequest(&osadminv1.GetExposedValueRequest{Name: "owner-only"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	g, err := alice.product().GetExposedValue(ctx, connect.NewRequest(&osadminv1.GetExposedValueRequest{Name: "owner-only"}))
	if err != nil || g.Msg.GetValue() != "sup-1" {
		t.Fatalf("an owner's owner-only value %v %v", g, err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, r := range k.reads {
		if strings.Contains(r, "OTHER") || strings.Contains(r, "PASSWORD") || strings.Contains(r, "sneakers-db") {
			t.Fatalf("the box asked the cluster for %s", r)
		}
	}
}

// With no product, or a bundle without product.yaml, nothing is exposed.
func TestNoProductExposesNothing(t *testing.T) {
	b := newBox(t, false, func(_ *box, o *osadmin.Options) { o.Exposed = &fakeKube{} })
	ctx := context.Background()
	alice := b.browser()
	alice.signIn("alice")
	l, err := alice.product().ListExposedValues(ctx, connect.NewRequest(&osadminv1.ListExposedValuesRequest{}))
	if err != nil || l.Msg.GetProduct() != "" || len(l.Msg.GetValues()) != 0 {
		t.Fatalf("%v %v", l, err)
	}
	_, err = alice.product().GetExposedValue(ctx, connect.NewRequest(&osadminv1.GetExposedValueRequest{Name: "setup-token"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}
