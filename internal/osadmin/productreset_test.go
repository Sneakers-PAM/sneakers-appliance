// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productreset"
)

// fakeReset is the product reset's k0s and disk steps: it records each
// step among the services' calls, so the test sees the order.
type fakeReset struct {
	b          *box
	clusterErr error
	removed    []string
}

func (f *fakeReset) note(what string) {
	f.b.services.mu.Lock()
	defer f.b.services.mu.Unlock()
	f.b.services.calls = append(f.b.services.calls, what)
}

func (f *fakeReset) Cluster(context.Context) (productreset.Counts, error) {
	f.note("cluster")
	if f.clusterErr != nil {
		return productreset.Counts{}, f.clusterErr
	}
	return productreset.Counts{Namespaces: 3, Objects: 41}, nil
}

func (f *fakeReset) Data(remove ...string) (int64, error) {
	f.note("data")
	f.removed = remove
	return 5000, nil
}

func resetBox(t *testing.T) (*box, *fakeReset, *browser) {
	t.Helper()
	fake := &fakeReset{}
	b := newBox(t, true, func(b *box, o *osadmin.Options) { fake.b = b; o.ProductReset = fake })
	alice := b.browser()
	alice.signIn("alice")
	alice.installProduct(t, "0.2.0")
	b.services.mu.Lock()
	b.services.calls = nil
	b.services.mu.Unlock()
	return b, fake, alice
}

// resetAs runs the closed shell's "<product> reset" as l.
func resetAs(b *box, l osadmin.Local, req *osadminv1.ResetProductRequest) (*osadminv1.ResetProductResponse, error) {
	h := b.srv.Handlers()
	var out *osadminv1.ResetProductResponse
	err := b.srv.RunLocalCall(context.Background(), l, osadminv1connect.ProductServiceResetProductProcedure, req, func(ctx context.Context) error {
		r, err := h.Product.ResetProduct(ctx, connect.NewRequest(req))
		if err == nil {
			out = r.Msg
		}
		return err
	})
	return out, err
}

func (b *box) ssh(admin string) osadmin.Local {
	return osadmin.Local{Admin: admin, KeyFP: b.keys[admin].fp, Source: "192.0.2.5"}
}

// An owner over SSH, with a new code and the product's name typed, stops
// the product and removes its objects with k0s up, then stops k0s, then
// takes the slot away (kept as the staged one) and removes the data and
// the box's records of the product. The box's own settings stay, and the
// reset is audited with its counts.
func TestAnOwnerResetsTheProductOverSSH(t *testing.T) {
	b, fake, alice := resetBox(t)
	platform := filepath.Join(b.state, "platform")
	records := []string{
		filepath.Join(platform, "box-secrets.json"), filepath.Join(platform, "switches"), filepath.Join(platform, "imported.json"),
		filepath.Join(b.state, "import"), filepath.Join(b.state, "osadmin-api", "exposed"),
	}
	b.services.running = true
	out, err := resetAs(b, b.ssh("alice"), &osadminv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "sneakers"})
	if err != nil {
		t.Fatal(err)
	}
	if got := b.services.log(); !slices.Equal(got, []string{"cluster", "stop k0s", "data"}) {
		t.Fatalf("steps %v", got)
	}
	if out.GetProduct() != "sneakers" || out.GetVersion() != "0.2.0" || out.GetNamespaces() != 3 || out.GetObjects() != 41 || out.GetBytesRemoved() != 5000 || out.GetStagedVersion() != "0.2.0" {
		t.Fatalf("answer %v", out)
	}
	for _, r := range records {
		if !slices.Contains(fake.removed, r) {
			t.Fatalf("%s isn't removed: %v", r, fake.removed)
		}
	}
	for _, r := range fake.removed {
		for _, keep := range []string{"access", "ssh", "osadmin", "box-values", "os-audit", "sealed", "backup"} {
			if filepath.Base(r) == keep {
				t.Fatalf("the reset removes the box's %s", r)
			}
		}
	}
	s := alice.productSlots(t)
	if s.GetInstalledVersion() != "" || s.GetStagedVersion() != "0.2.0" || s.GetRunning() {
		t.Fatalf("slots after the reset %v", s)
	}
	if len(b.netd.servicePorts) != 0 {
		t.Fatalf("the product's ports are still open: %v", b.netd.servicePorts)
	}
	e := lastEntry(t, b.log, "product.reset")
	if e.Actor != "alice" || e.Outcome != "ok" || e.Target != "Sneakers" || e.Detail["surface"] != osadmin.SurfaceSSH ||
		e.Detail["namespaces"] != "3" || e.Detail["objects"] != "41" || e.Detail["bytes"] != "5000" || e.Detail["version"] != "0.2.0" {
		t.Fatalf("audit %+v", e)
	}
	g := alice.upgrades(t)
	if h := g.GetHistory()[0]; h.GetAction() != "reset" || h.GetTarget() != product || h.GetVersion() != "0.2.0" || h.GetOutcome() != "ok" {
		t.Fatalf("history %v", h)
	}
	// Apply on the Product card installs the kept bundle again.
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	if s := alice.productSlots(t); s.GetInstalledVersion() != "0.2.0" {
		t.Fatalf("slots after the reinstall %v", s)
	}
}

// The box's host name confirms it as well as the product's name; k0s that
// doesn't run is started first, so the product's objects can go.
func TestTheHostNameConfirmsAndAStoppedK0sStartsFirst(t *testing.T) {
	b, _, _ := resetBox(t)
	b.services.running = false
	if _, err := resetAs(b, b.ssh("alice"), &osadminv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "box1.sneakers.example.org"}); err != nil {
		t.Fatal(err)
	}
	if got := b.services.log(); !slices.Equal(got, []string{"start k0s", "cluster", "stop k0s", "data"}) {
		t.Fatalf("steps %v", got)
	}
}

// Every way in but an owner's SSH login with a new code and the typed name
// is refused before anything is touched, and audited.
func TestTheResetIsAnOwnersOverSSHWithANewCode(t *testing.T) {
	b, _, alice := resetBox(t)
	cases := []struct {
		name   string
		l      osadmin.Local
		req    func() *osadminv1.ResetProductRequest
		code   connect.Code
		symbol string
	}{
		{"an admin", b.ssh("bob"), func() *osadminv1.ResetProductRequest {
			return &osadminv1.ResetProductRequest{TotpCode: b.code("bob"), Confirm: "sneakers"}
		}, connect.CodePermissionDenied, "ACCESS_FORBIDDEN"},
		{"the console", osadmin.Local{}, func() *osadminv1.ResetProductRequest { return &osadminv1.ResetProductRequest{Confirm: "sneakers"} }, connect.CodePermissionDenied, "ACCESS_FORBIDDEN"},
		{"no code", b.ssh("alice"), func() *osadminv1.ResetProductRequest { return &osadminv1.ResetProductRequest{Confirm: "sneakers"} }, connect.CodeInvalidArgument, "ACCESS_CONFIRM"},
		{"a wrong code", b.ssh("alice"), func() *osadminv1.ResetProductRequest {
			return &osadminv1.ResetProductRequest{TotpCode: "000000", Confirm: "sneakers"}
		}, connect.CodeUnauthenticated, "ACCESS_CREDENTIALS"},
		{"no name", b.ssh("alice"), func() *osadminv1.ResetProductRequest {
			return &osadminv1.ResetProductRequest{TotpCode: b.code("alice")}
		}, connect.CodeInvalidArgument, "ACCESS_CONFIRM"},
		{"another name", b.ssh("alice"), func() *osadminv1.ResetProductRequest {
			return &osadminv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "yes"}
		}, connect.CodeInvalidArgument, "ACCESS_CONFIRM"},
	}
	for _, c := range cases {
		_, err := resetAs(b, c.l, c.req())
		if err == nil {
			t.Fatalf("%s: reset", c.name)
		}
		if connect.CodeOf(err) != c.code || !strings.Contains(err.Error(), c.symbol) {
			t.Fatalf("%s: want %v %s, got %v", c.name, c.code, c.symbol, err)
		}
		if e := lastEntry(t, b.log, "product.reset"); e.Outcome != "refused" {
			t.Fatalf("%s: audit %+v", c.name, e)
		}
	}
	// :8443 has no way to it, an owner's fresh session included.
	alice.stepUp("alice")
	_, err := alice.product().ResetProduct(context.Background(), connect.NewRequest(&osadminv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "sneakers"}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
	if got := b.services.log(); len(got) != 0 {
		t.Fatalf("a refused reset ran %v", got)
	}
	if s := alice.productSlots(t); s.GetInstalledVersion() != "0.2.0" {
		t.Fatalf("slots %v", s)
	}
}

// A step that fails stops the reset there: k0s isn't stopped and the
// product stays installed, so the reset can run again.
func TestAFailedClusterStepKeepsTheProduct(t *testing.T) {
	b, fake, alice := resetBox(t)
	b.services.running = true
	fake.clusterErr = codes.New(codes.ProductReset, "the product's namespace didn't go")
	_, err := resetAs(b, b.ssh("alice"), &osadminv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "sneakers"})
	symbolIn(t, err, connect.CodeFailedPrecondition, "PRODUCT_RESET")
	if got := b.services.log(); !slices.Equal(got, []string{"cluster"}) {
		t.Fatalf("steps %v", got)
	}
	if s := alice.productSlots(t); s.GetInstalledVersion() != "0.2.0" {
		t.Fatalf("slots %v", s)
	}
	if e := lastEntry(t, b.log, "product.reset"); e.Outcome != "refused" || e.Code != "PRODUCT_RESET" || e.Detail["step"] != "cluster" {
		t.Fatalf("audit %+v", e)
	}
	if g := alice.upgrades(t); g.GetHistory()[0].GetAction() != "reset" || g.GetHistory()[0].GetOutcome() != "failed" {
		t.Fatalf("history %v", g.GetHistory()[0])
	}
}

// With no product there's nothing to reset.
func TestNoProductHasNothingToReset(t *testing.T) {
	fake := &fakeReset{}
	b := newBox(t, false, func(b *box, o *osadmin.Options) { fake.b = b; o.ProductReset = fake })
	_, err := resetAs(b, b.ssh("alice"), &osadminv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "sneakers"})
	symbolIn(t, err, connect.CodeFailedPrecondition, "PRODUCT_NOT_INSTALLED")
	if got := b.services.log(); len(got) != 0 {
		t.Fatalf("steps %v", got)
	}
}

// An open elevated shell holds the reset, as it holds a product update.
func TestAnElevatedShellHoldsTheReset(t *testing.T) {
	b, _, _ := resetBox(t)
	b.elevated()
	_, err := resetAs(b, b.ssh("alice"), &osadminv1.ResetProductRequest{TotpCode: b.code("alice"), Confirm: "sneakers"})
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_ELEVATED")
	if got := b.services.log(); len(got) != 0 {
		t.Fatalf("steps %v", got)
	}
	if b.srv.Maintenance() {
		t.Fatal("a refused reset left maintenance on")
	}
}
