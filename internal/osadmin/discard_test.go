// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
)

const base = osadminv1.UpdateTarget_UPDATE_TARGET_BASE

func (br *browser) upgrades(t *testing.T) *osadminv1.GetUpgradesResponse {
	t.Helper()
	g, err := br.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return g.Msg
}

func (br *browser) discard(id string, target osadminv1.UpdateTarget) (*osadminv1.DiscardUpdateResponse, error) {
	r, err := br.upgrade().DiscardUpdate(context.Background(), connect.NewRequest(&osadminv1.DiscardUpdateRequest{UploadId: id, Target: target}))
	if err != nil {
		return nil, err
	}
	return r.Msg, nil
}

// uploadNamed posts body with the file name the page sends, and returns
// the status and the body of the answer.
func (br *browser) uploadNamed(t *testing.T, body io.Reader, name string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, br.b.ts.URL+"/upload", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-File-Name", name)
	resp, err := br.hc.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (b *box) uploadFiles(t *testing.T) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(b.state, "osadmin-api", "uploads", "*"))
	return m
}

func TestAHeldUploadBlocksTheNextUntilItIsDiscarded(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	file := bin(t, b.sign, b.enc, full(release.ChannelProduction))
	code, _ := alice.uploadNamed(t, bytes.NewReader(file), "sneakers-appliance-0.2.0-amd64.bin")
	if code != http.StatusOK {
		t.Fatalf("upload %d", code)
	}
	held := alice.upgrades(t).GetHeldUpload()
	if held.GetUploadId() == "" || held.GetFileName() != "sneakers-appliance-0.2.0-amd64.bin" || held.GetSize() != int64(len(file)) || held.GetSource() != "upload" || held.GetReceivedAt() == nil {
		t.Fatalf("held %v", held)
	}
	code, body := alice.uploadNamed(t, bytes.NewReader(file), "again.bin")
	if code != http.StatusConflict || !strings.Contains(body, "UPGRADE_BUSY") {
		t.Fatalf("a second upload: %d %s", code, body)
	}
	b.mirrorFiles["sneakers-appliance-0.2.0-amd64.bin"] = file
	pol := &osadminv1.UpgradePolicy{Mode: "manual", WindowStart: "02:00", WindowMinutes: 120, MirrorUrl: b.mirror.URL}
	if _, err := alice.upgrade().SetUpgradePolicy(context.Background(), connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol})); err != nil {
		t.Fatal(err)
	}
	_, err := alice.upgrade().FetchUpdate(context.Background(), connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "sneakers-appliance-0.2.0-amd64.bin"}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_BUSY")

	if _, err := alice.discard(held.GetUploadId(), 0); err != nil {
		t.Fatal(err)
	}
	if f := b.uploadFiles(t); len(f) != 0 {
		t.Fatalf("left behind %v", f)
	}
	if alice.upgrades(t).GetHeldUpload() != nil {
		t.Fatal("still held")
	}
	if e := lastEntry(t, b.log, "upgrade.discard"); e.Outcome != "ok" || e.Actor != "alice" || e.Detail["upload"] != held.GetUploadId() {
		t.Fatalf("%+v", e)
	}
	_, err = alice.discard(held.GetUploadId(), 0)
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_UPLOAD")
	if code, _ := alice.uploadNamed(t, bytes.NewReader(file), "x.bin"); code != http.StatusOK {
		t.Fatalf("an upload after the discard: %d", code)
	}
}

// A browser that aborts its upload leaves no file, and while the bytes
// come in a second upload is refused.
func TestAnAbortedUploadLeavesNothingBehind(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = alice.uploadNamed(t, pr, "slow.bin")
	}()
	if _, err := pw.Write(bytes.Repeat([]byte("x"), 64<<10)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return alice.upgrades(t).GetReceiving() })
	code, body := alice.uploadNamed(t, bytes.NewReader([]byte("y")), "second.bin")
	if code != http.StatusConflict || !strings.Contains(body, "UPGRADE_BUSY") {
		t.Fatalf("an upload during an upload: %d %s", code, body)
	}
	_ = pw.CloseWithError(io.ErrUnexpectedEOF)
	<-done
	waitFor(t, func() bool { return !alice.upgrades(t).GetReceiving() && len(b.uploadFiles(t)) == 0 })
	if alice.upgrades(t).GetHeldUpload() != nil {
		t.Fatal("an aborted upload is held")
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDiscardUnstagesTheBaseRelease(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	_, err := alice.discard("", base)
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_NOT_STAGED")
	id, _ := alice.upload(t, bin(t, b.sign, b.enc, full(release.ChannelProduction)))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	got, err := alice.discard("", base)
	if err != nil || got.GetVersion() != "0.2.0" || b.init.unstaged != 1 {
		t.Fatalf("%v %v %d", got, err, b.init.unstaged)
	}
	if g := alice.upgrades(t); g.GetStagedVersion() != "" || g.GetHistory()[0].GetAction() != "discard" || g.GetHistory()[0].GetVersion() != "0.2.0" {
		t.Fatalf("%v", g)
	}
	if e := lastEntry(t, b.log, "upgrade.discard"); e.Outcome != "ok" || e.Detail["version"] != "0.2.0" || e.Target != "release 0.2.0" {
		t.Fatalf("%+v", e)
	}
}

func TestDiscardUnstagesTheProduct(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	alice.installProduct(t, "0.2.0")
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.3.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	got, err := alice.discard("", product)
	if err != nil || got.GetVersion() != "0.3.0" {
		t.Fatalf("%v %v", got, err)
	}
	if p := alice.productSlots(t); p.GetStagedVersion() != "" || p.GetInstalledVersion() != "0.2.0" {
		t.Fatalf("%v", p)
	}
}

func TestDiscardIsAnOwnersAndWaitsForAStage(t *testing.T) {
	b := newBox(t, true)
	bob := b.browser()
	bob.signIn("bob")
	_, err := bob.discard("", base)
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")

	alice := b.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, bin(t, b.sign, b.enc, full(release.ChannelProduction)))
	var during error
	var duringUpload int
	b.init.duringStage = func() {
		_, during = alice.discard(id, 0)
		duringUpload, _ = alice.uploadNamed(t, bytes.NewReader([]byte("z")), "z.bin")
	}
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	symbolIn(t, during, connect.CodeFailedPrecondition, "UPGRADE_BUSY")
	if duringUpload != http.StatusConflict {
		t.Fatalf("an upload during a stage: %d", duringUpload)
	}
}

func TestAProductBundleOutsideItsBaseRangeIsRefusedAtVerify(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, productBinH(t, b.sign, b.enc, updatepkg.Header{Version: "0.2.0", Arch: "amd64", Kind: updatepkg.KindProduct, MinBase: "0.1.1", MaxBase: "0.2.0", Channel: release.ChannelProduction}))
	err := stage(alice, id)
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_PRODUCT_BASE")
	if d := err.Error(); !strings.Contains(d, "0.1.1 to 0.2.0") || !strings.Contains(d, "0.1.0") {
		t.Fatalf("the refusal names the range and the running base: %s", d)
	}
	if b.keyReads != 0 || len(b.uploadFiles(t)) != 0 {
		t.Fatal("a refused bundle was decrypted or kept")
	}
	id, _ = alice.upload(t, productBinH(t, b.sign, b.enc, updatepkg.Header{Version: "0.2.0", Arch: "amd64", Kind: updatepkg.KindProduct, MinBase: "0.1.0", Channel: release.ChannelProduction}))
	if err := stage(alice, id); err != nil {
		t.Fatalf("inside the range: %v", err)
	}
}

func TestABaseReleaseOutsideTheInstalledProductsRangeNeedsAnOverride(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, productBinH(t, b.sign, b.enc, updatepkg.Header{Version: "0.2.0", Arch: "amd64", Kind: updatepkg.KindProduct, MinBase: "0.1.0", MaxBase: "0.1.9", Channel: release.ChannelProduction}))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: product, TotpCode: b.code("alice")})); err != nil {
		t.Fatal(err)
	}
	id, _ = alice.upload(t, bin(t, b.sign, b.enc, full(release.ChannelProduction)))
	err := stage(alice, id)
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_PRODUCT_BASE")
	if d := err.Error(); !strings.Contains(d, "0.1.0 to 0.1.9") || !strings.Contains(d, "0.2.0") {
		t.Fatalf("the refusal names the product's range and the new base: %s", d)
	}
	if len(b.init.staged) != 0 || len(b.uploadFiles(t)) == 0 {
		t.Fatal("the refused base staged, or its upload was dropped so it can't be staged with the override")
	}
	if _, err := alice.upgrade().StageUpdate(context.Background(), connect.NewRequest(&osadminv1.StageUpdateRequest{UploadId: id, OverrideProductRange: true})); err != nil {
		t.Fatalf("with the override: %v", err)
	}
	if e := lastEntry(t, b.log, "upgrade.stage"); e.Detail["override"] != "product-range" {
		t.Fatalf("the override is audited: %+v", e)
	}
}

// A bundle sealed before the range existed names its bases, and stays
// accepted.
func TestAnOlderBundleWithBasesOnlyStillStages(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, productBin(t, b.sign, b.enc, "0.2.0", "0.1.0"))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.state, "product")); err != nil {
		t.Fatal(err)
	}
}

func TestTheListOffersByBaseRangeAndNamesIt(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	h := func(v, minBase, maxBase string) []byte {
		return productBinH(t, b.sign, b.enc, updatepkg.Header{Version: v, Arch: "amd64", Kind: updatepkg.KindProduct, MinBase: minBase, MaxBase: maxBase, Channel: release.ChannelProduction})
	}
	b.mirrorFiles[updatepkg.IndexName] = index(t, h("0.2.0", "0.1.0", "0.1.5"), h("0.3.0", "0.1.1", ""))
	pol := &osadminv1.UpgradePolicy{Mode: "manual", WindowStart: "02:00", WindowMinutes: 120, MirrorUrl: b.mirror.URL}
	if _, err := alice.upgrade().SetUpgradePolicy(ctx, connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol})); err != nil {
		t.Fatal(err)
	}
	l, err := alice.upgrade().ListProductVersions(ctx, connect.NewRequest(&osadminv1.ListProductVersionsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	vs := l.Msg.GetVersions()
	if len(vs) != 1 || vs[0].GetVersion() != "0.2.0" || vs[0].GetMinBase() != "0.1.0" || vs[0].GetMaxBase() != "0.1.5" {
		t.Fatalf("offered %v", l.Msg)
	}
}
