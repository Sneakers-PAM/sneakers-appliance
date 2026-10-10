// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"filippo.io/age"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1/osadminv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

const product = osadminv1.UpdateTarget_UPDATE_TARGET_PRODUCT

// productBin makes a product bundle .bin for version, fitting bases, the
// way the release build does: the fixture bundle, packed and signed.
func productBin(t *testing.T, sign testpki.ECKey, enc *age.X25519Identity, version string, bases ...string) []byte {
	t.Helper()
	return productBinH(t, sign, enc, updatepkg.Header{Version: version, Arch: "amd64", Kind: updatepkg.KindProduct, Bases: bases, Channel: release.ChannelProduction})
}

// productBinH is productBin for a header of the test's own.
func productBinH(t *testing.T, sign testpki.ECKey, enc *age.X25519Identity, want updatepkg.Header) []byte {
	t.Helper()
	tree, _ := fixtures.ProductTree(t, fixtures.LabKeys(t), "amd64", nil)
	dir := t.TempDir()
	for name, f := range tree {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, f.Data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var payload, ct, out bytes.Buffer
	if err := updatepkg.TarDir(dir, &payload); err != nil {
		t.Fatal(err)
	}
	h, err := updatepkg.Encrypt(&payload, want, enc.Recipient(), &ct)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := updatepkg.Seal(&out, hdr, sign.BlobBundle(t, hdr), &ct); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func (br *browser) productSlots(t *testing.T) *osadminv1.ProductSlots {
	t.Helper()
	g, err := br.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return g.Msg.GetProduct()
}

func (br *browser) installProduct(t *testing.T, version string) {
	t.Helper()
	id, _ := br.upload(t, productBin(t, br.b.sign, br.b.enc, version, "0.1.0"))
	if err := stage(br, id); err != nil {
		t.Fatal(err)
	}
	if _, err := br.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: br.b.code("alice")})); err != nil {
		t.Fatal(err)
	}
}

func TestTheFirstProductInstallIsAStageAndAnApply(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	if s := alice.productSlots(t); s.GetInstalledVersion() != "" || s.GetRunning() {
		t.Fatalf("a new box has a product: %v", s)
	}
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	st, err := alice.upgrade().StageUpdate(ctx, connect.NewRequest(&osadminv1.StageUpdateRequest{UploadId: id}))
	if err != nil {
		t.Fatal(err)
	}
	if st.Msg.GetPackage().GetTarget() != product || st.Msg.GetPackage().GetKind() != "product" {
		t.Fatalf("staged %v", st.Msg.GetPackage())
	}
	if s := alice.productSlots(t); s.GetStagedVersion() != "0.2.0" || s.GetInstalledVersion() != "" {
		t.Fatalf("slots %v", s)
	}
	if len(b.init.staged) != 0 || len(b.services.log()) != 0 || len(b.netd.servicePorts) != 0 {
		t.Fatal("staging a product bundle touched the base slots, the services or the ports")
	}
	if _, err := alice.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	if got := b.services.log(); !slices.Equal(got, []string{"stop k0s", "start k0s"}) {
		t.Fatalf("services %v", got)
	}
	if !slices.Equal(b.netd.servicePorts, []uint32{80, 443}) {
		t.Fatalf("ports %v", b.netd.servicePorts)
	}
	if b.init.activated != 0 || b.init.reboots != 0 {
		t.Fatal("a product apply activated a base release or rebooted")
	}
	s := alice.productSlots(t)
	if s.GetInstalledVersion() != "0.2.0" || s.GetPreviousVersion() != "" || !s.GetRunning() {
		t.Fatalf("slots %v", s)
	}
	g, _ := alice.upgrade().GetUpgrades(ctx, connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if h := g.Msg.GetHistory()[0]; h.GetAction() != "apply" || h.GetTarget() != product || h.GetVersion() != "0.2.0" || h.GetOutcome() != "ok" {
		t.Fatalf("history %v", h)
	}
	if e := lastEntry(t, b.log, "upgrade.apply"); e.Outcome != "ok" || e.Target != "product" {
		t.Fatalf("%+v", e)
	}
	if _, err := os.Stat(filepath.Join(b.state, "product", "current", "k0s")); err != nil {
		t.Fatalf("k0s in the current slot: %v", err)
	}
}

func TestAProductBundleIsRefusedBeforeUnpacking(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	for _, tc := range []struct {
		name, symbol string
		body         []byte
	}{
		{"another base", "UPGRADE_PRODUCT_BASE", productBin(t, b.sign, b.enc, "0.2.0", "0.0.9")},
		{"another signing key", "UPGRADE_SIGNATURE", productBin(t, testpki.ECDSA(t), b.enc, "0.2.0", "0.1.0")},
	} {
		id, _ := alice.upload(t, tc.body)
		err := stage(alice, id)
		if err == nil || !bytes.Contains([]byte(err.Error()), []byte(tc.symbol)) {
			t.Errorf("%s: got %v", tc.name, err)
		}
		if b.keyReads != 0 {
			t.Fatalf("%s was decrypted", tc.name)
		}
		if s := alice.productSlots(t); s.GetStagedVersion() != "" {
			t.Fatalf("%s was staged", tc.name)
		}
		if err := stage(alice, id); err == nil || !bytes.Contains([]byte(err.Error()), []byte("UPGRADE_UPLOAD")) {
			t.Errorf("%s: a refused upload is removed: %v", tc.name, err)
		}
	}
}

func TestAProductUpgradeKeepsThePreviousSlotAsTheWayBack(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	alice.installProduct(t, "0.2.0")
	_, err := alice.upgrade().RevertUpdate(ctx, connect.NewRequest(&osadminv1.RevertUpdateRequest{Target: product, TotpCode: b.code("alice")}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_NO_PREVIOUS")
	alice.installProduct(t, "0.3.0")
	if s := alice.productSlots(t); s.GetInstalledVersion() != "0.3.0" || s.GetPreviousVersion() != "0.2.0" {
		t.Fatalf("slots %v", s)
	}
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	symbolIn(t, stage(alice, id), connect.CodeFailedPrecondition, "UPGRADE_DOWNGRADE")
	if _, err := alice.upgrade().RevertUpdate(ctx, connect.NewRequest(&osadminv1.RevertUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	if s := alice.productSlots(t); s.GetInstalledVersion() != "0.2.0" || s.GetPreviousVersion() != "0.3.0" {
		t.Fatalf("slots after the revert %v", s)
	}
	if b.init.rollbacks != 0 || b.init.reboots != 0 {
		t.Fatal("a product revert rolled the base back or rebooted")
	}
}

func TestAProductApplyWaitsForAnOpenElevatedShell(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	b.elevated()
	_, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_ELEVATED")
	if len(b.services.log()) != 0 || alice.productSlots(t).GetInstalledVersion() != "" {
		t.Fatal("the product was applied under an elevated shell")
	}
}

func TestTheWindowAppliesAStagedProduct(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	open := b.clk.Now().Local().Add(-10 * time.Minute).Format("15:04")
	pol := &osadminv1.UpgradePolicy{Mode: "automatic", WindowStart: open, WindowMinutes: 60}
	if _, err := alice.upgrade().SetUpgradePolicy(ctx, connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol})); err != nil {
		t.Fatal(err)
	}
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	b.srv.UpgradeWindowTick(ctx)
	b.srv.UpgradeWindowTick(ctx)
	if s := alice.productSlots(t); s.GetInstalledVersion() != "0.2.0" {
		t.Fatalf("slots %v", s)
	}
	if got := b.services.log(); len(got) != 2 {
		t.Fatalf("applied more than once: %v", got)
	}
}

func index(t *testing.T, bins ...[]byte) []byte {
	t.Helper()
	var idx updatepkg.Index
	for _, bb := range bins {
		p, err := updatepkg.Read(bytes.NewReader(bb), int64(len(bb)))
		if err != nil {
			t.Fatal(err)
		}
		idx.Products = append(idx.Products, updatepkg.EntryOf(p.Header, int64(len(bb))))
	}
	out, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestListThenFetchFromTheMirrorThenDirect(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	_, err := alice.upgrade().ListProductVersions(ctx, connect.NewRequest(&osadminv1.ListProductVersionsRequest{}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_AIR_GAPPED")
	if b.mirrorHit != 0 {
		t.Fatal("an air-gapped box made a network fetch")
	}

	v2, v3, other := productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"), productBin(t, b.sign, b.enc, "0.3.0", "0.1.0"), productBin(t, b.sign, b.enc, "0.4.0", "0.0.9")
	// The mirror has the index; direct fetches are allowed too.
	b.mirrorFiles[updatepkg.IndexName] = index(t, v2, v3, other)
	b.mirrorFiles["direct/latest/download/sneakers-product-0.3.0-amd64.bin"] = v3
	pol := &osadminv1.UpgradePolicy{Mode: "manual", WindowStart: "02:00", WindowMinutes: 120, MirrorUrl: b.mirror.URL, Direct: true}
	if _, err := alice.upgrade().SetUpgradePolicy(ctx, connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol})); err != nil {
		t.Fatal(err)
	}
	l, err := alice.upgrade().ListProductVersions(ctx, connect.NewRequest(&osadminv1.ListProductVersionsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	vs := l.Msg.GetVersions()
	if l.Msg.GetBaseVersion() != "0.1.0" || len(vs) != 2 || vs[0].GetVersion() != "0.3.0" || vs[0].GetSource() != "mirror" {
		t.Fatalf("offered %v", l.Msg)
	}
	// The mirror doesn't have the file: it comes from the release source.
	f, err := alice.upgrade().FetchUpdate(ctx, connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: vs[0].GetFileName()}))
	if err != nil || f.Msg.GetSource() != "direct" {
		t.Fatalf("fetch %v %v", f, err)
	}
	if err := stage(alice, f.Msg.GetUploadId()); err != nil {
		t.Fatal(err)
	}
	if s := alice.productSlots(t); s.GetStagedVersion() != "0.3.0" {
		t.Fatalf("slots %v", s)
	}

	// Without a mirror, the index comes from the release source.
	delete(b.mirrorFiles, updatepkg.IndexName)
	idx := index(t, v2)
	b.mirrorFiles["direct/latest/download/"+updatepkg.IndexName] = idx
	b.mirrorFiles["direct/latest/download/"+updatepkg.IndexName+".sigstore.json"] = b.sign.BlobBundle(t, idx)
	pol.MirrorUrl = ""
	if _, err := alice.upgrade().SetUpgradePolicy(ctx, connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol})); err != nil {
		t.Fatal(err)
	}
	g, _ := alice.upgrade().GetUpgrades(ctx, connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if g.Msg.GetAirGapped() || !g.Msg.GetDirectAvailable() {
		t.Fatalf("upgrades %v", g.Msg)
	}
	l, err = alice.upgrade().ListProductVersions(ctx, connect.NewRequest(&osadminv1.ListProductVersionsRequest{}))
	if err != nil || len(l.Msg.GetVersions()) != 1 || l.Msg.GetVersions()[0].GetSource() != "direct" {
		t.Fatalf("direct offer %v %v", l, err)
	}
}

// The product slots carry the installed product's name, so the :8443 nav
// can show the product's own section only once one is installed.
func TestTheProductSlotsNameTheInstalledProduct(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	if s := alice.productSlots(t); s.GetName() != "" {
		t.Fatalf("a box with no product names one: %v", s)
	}
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if s := alice.productSlots(t); s.GetName() != "" {
		t.Fatalf("a staged product is named before it's installed: %v", s)
	}
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	if s := alice.productSlots(t); s.GetName() != "Sneakers" {
		t.Fatalf("installed product name %q", s.GetName())
	}
}

// Status carries the product's slots as Updates gives them, for the
// console's status screen.
func TestStatusCarriesTheProductSlots(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	status := func() *osadminv1.ProductSlots {
		t.Helper()
		st, err := osadminv1connect.NewStatusServiceClient(alice.hc, b.ts.URL).GetStatus(ctx, connect.NewRequest(&osadminv1.GetStatusRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		return st.Msg.GetProduct()
	}
	if p := status(); p.GetInstalledVersion() != "" || p.GetRunning() {
		t.Fatalf("a new box's Status has a product: %v", p)
	}
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if p := status(); p.GetStagedVersion() != "0.2.0" || p.GetInstalledVersion() != "" {
		t.Fatalf("Status after the stage: %v", p)
	}
	if _, err := alice.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	if p := status(); p.GetInstalledVersion() != "0.2.0" || p.GetStagedVersion() != "" || !p.GetRunning() {
		t.Fatalf("Status after the install: %v", p)
	}
}

// fakeBoxSecrets records the slots it made box secrets for, and what the
// services had been asked by then.
type fakeBoxSecrets struct {
	b     *box
	slots []string
	seen  [][]string
	err   error
}

func (f *fakeBoxSecrets) Ensure(slot string) error {
	cur, _ := filepath.EvalSymlinks(filepath.Join(f.b.state, "product", "current"))
	if got, _ := filepath.EvalSymlinks(slot); got != cur {
		slot = "not the current slot " + slot
	}
	f.slots = append(f.slots, slot)
	f.seen = append(f.seen, f.b.services.log())
	return f.err
}

// A product apply and a revert make the current slot's box secrets after
// the switch and before k0s restarts, so the product's first start already
// has them; a failure stops the apply before k0s is touched.
func TestAProductApplyMakesTheBoxSecretsBeforeK0sStarts(t *testing.T) {
	fake := &fakeBoxSecrets{}
	b := newBox(t, false, func(b *box, o *osadmin.Options) { fake.b = b; o.BoxSecrets = fake })
	alice := b.browser()
	alice.signIn("alice")
	alice.installProduct(t, "0.2.0")
	alice.installProduct(t, "0.3.0")
	if len(fake.slots) != 2 {
		t.Fatalf("box secrets made %d times", len(fake.slots))
	}
	for i, s := range fake.slots {
		if strings.HasPrefix(s, "not") {
			t.Fatalf("made for %s", s)
		}
		if n := len(fake.seen[i]); n != 2*i {
			t.Fatalf("made when the services had %v, want before the restart", fake.seen[i])
		}
	}
	if _, err := alice.upgrade().RevertUpdate(context.Background(), connect.NewRequest(&osadminv1.RevertUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	if len(fake.slots) != 3 {
		t.Fatalf("a revert didn't make the box secrets: %d", len(fake.slots))
	}
	fake.err = errors.New("no random source")
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.4.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	before := len(b.services.log())
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err == nil {
		t.Fatal("the apply went on without its box secrets")
	}
	if got := b.services.log()[before:]; len(got) != 0 {
		t.Fatalf("services after a failed box secrets step %v", got)
	}
}
