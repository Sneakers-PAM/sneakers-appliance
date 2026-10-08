// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
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
)

// bin makes a .bin the way the release workflow does, from a layout
// directory holding one file.
func bin(t *testing.T, sign testpki.ECKey, enc *age.X25519Identity, h updatepkg.Header) []byte {
	t.Helper()
	layout := t.TempDir()
	if err := os.WriteFile(filepath.Join(layout, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var payload, ct, out bytes.Buffer
	if err := updatepkg.TarDir(layout, &payload); err != nil {
		t.Fatal(err)
	}
	h, err := updatepkg.Encrypt(&payload, h, enc.Recipient(), &ct)
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

func full(channel string) updatepkg.Header {
	return updatepkg.Header{Version: "0.2.0", Arch: "amd64", Kind: updatepkg.KindFull, Channel: channel}
}

func (br *browser) upgrade() osadminv1connect.UpgradeServiceClient {
	return osadminv1connect.NewUpgradeServiceClient(br.hc, br.b.ts.URL)
}

func (br *browser) upload(t *testing.T, body []byte) (string, int) {
	t.Helper()
	resp, err := br.hc.Post(br.b.ts.URL+"/upload", "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		UploadID string `json:"uploadId"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.UploadID, resp.StatusCode
}

func stage(br *browser, id string) error {
	_, err := br.upgrade().StageUpdate(context.Background(), connect.NewRequest(&osadminv1.StageUpdateRequest{UploadId: id}))
	return err
}

// unpacked reports whether any upload was unpacked.
func (b *box) unpacked(t *testing.T) bool {
	t.Helper()
	dirs, _ := filepath.Glob(filepath.Join(b.state, "osadmin", "uploads", "*.d"))
	return len(dirs) > 0 || b.keyReads > 0
}

func TestUploadVerifyThenStage(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	id, code := alice.upload(t, bin(t, b.sign, b.enc, full(release.ChannelProduction)))
	if code != http.StatusOK || id == "" {
		t.Fatalf("upload %d %q", code, id)
	}
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if b.keyReads != 1 || len(b.init.staged) != 1 {
		t.Fatalf("decrypted once, staged once: %d %v", b.keyReads, b.init.staged)
	}
	if _, err := os.Stat(filepath.Join(b.init.staged[0], "oci-layout")); err != nil {
		t.Fatalf("init stages the unpacked layout: %v", err)
	}
	g, err := alice.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if err != nil || g.Msg.GetPolicy().GetWindowStart() != osadmin.DefaultPolicy().WindowStart || g.Msg.GetStagedVersion() != "0.2.0" || !g.Msg.GetAirGapped() || len(g.Msg.GetHistory()) != 1 || g.Msg.GetHistory()[0].GetOutcome() != "ok" {
		t.Fatalf("%v %v", g, err)
	}
	if e := lastEntry(t, b.log, "upgrade.stage"); e.Outcome != "ok" || e.Detail["version"] != "0.2.0" {
		t.Fatalf("%+v", e)
	}
}

func TestAnUnverifiedBinIsNeverUnpacked(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	tampered := bin(t, b.sign, b.enc, full(release.ChannelProduction))
	tampered[len(tampered)-1] ^= 0xff
	for _, tc := range []struct {
		name, symbol string
		body         []byte
	}{
		{"another signing key", "UPGRADE_SIGNATURE", bin(t, testpki.ECDSA(t), b.enc, full(release.ChannelProduction))},
		{"a changed payload", "UPGRADE_SIGNATURE", tampered},
		{"a lab package on a production box", "UPGRADE_CHANNEL", bin(t, testpki.ECDSA(t), other, full(release.ChannelLab))},
		{"not a package", "UPGRADE_FORMAT", []byte("hello")},
		{"a patch for another base", "UPGRADE_PATCH_BASE", bin(t, b.sign, b.enc, updatepkg.Header{Version: "0.1.1", Arch: "amd64", Kind: updatepkg.KindPatch, Bases: []string{"0.0.9"}, Channel: release.ChannelProduction})},
	} {
		id, _ := alice.upload(t, tc.body)
		err := stage(alice, id)
		if err == nil || !bytes.Contains([]byte(err.Error()), []byte(tc.symbol)) {
			t.Errorf("%s: got %v", tc.name, err)
		}
		if b.unpacked(t) || len(b.init.staged) != 0 {
			t.Fatalf("%s was unpacked", tc.name)
		}
		if err := stage(alice, id); err == nil || !bytes.Contains([]byte(err.Error()), []byte("UPGRADE_UPLOAD")) {
			t.Errorf("%s: a refused upload is removed: %v", tc.name, err)
		}
	}
	if e := lastEntry(t, b.log, "upgrade.stage"); e.Outcome != "refused" {
		t.Fatalf("%+v", e)
	}
}

func TestAPatchForTheRunningVersionStages(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, bin(t, b.sign, b.enc, updatepkg.Header{Version: "0.1.1", Arch: "amd64", Kind: updatepkg.KindPatch, Bases: []string{"0.1.0"}, Channel: release.ChannelProduction}))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
}

func TestUploadNeedsCSRF(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	alice.csrf = ""
	if _, code := alice.upload(t, []byte("x")); code != http.StatusForbidden {
		t.Fatalf("got %d", code)
	}
	if _, code := b.browser().upload(t, []byte("x")); code != http.StatusForbidden {
		t.Fatalf("no session: %d", code)
	}
}

func TestAirGapMeansNoFetch(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	name := "sneakers-appliance-0.2.0-amd64.bin"
	b.mirrorFiles[name] = bin(t, b.sign, b.enc, full(release.ChannelProduction))
	_, err := alice.upgrade().FetchUpdate(ctx, connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: name}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_AIR_GAPPED")
	if b.mirrorHit != 0 {
		t.Fatal("an air-gapped box made a network fetch")
	}

	pol := &osadminv1.UpgradePolicy{Mode: "manual", WindowStart: "02:00", WindowMinutes: 120, MirrorUrl: "http://mirror.sneakers.example.org"}
	_, err = alice.upgrade().SetUpgradePolicy(ctx, connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol}))
	symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_CONFIRM")
	pol.MirrorUrl = b.mirror.URL + "/"
	if _, err := alice.upgrade().SetUpgradePolicy(ctx, connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol})); err != nil {
		t.Fatal(err)
	}
	_, err = alice.upgrade().FetchUpdate(ctx, connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "../etc/passwd"}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_UPLOAD")
	f, err := alice.upgrade().FetchUpdate(ctx, connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: name}))
	if err != nil || b.mirrorHit != 1 {
		t.Fatalf("%v %v", f, err)
	}
	if err := stage(alice, f.Msg.GetUploadId()); err != nil {
		t.Fatal(err)
	}
	_, err = alice.upgrade().FetchUpdate(ctx, connect.NewRequest(&osadminv1.FetchUpdateRequest{FileName: "sneakers-appliance-9.9.9-amd64.bin"}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_UPLOAD")
}

func TestApplyAndRevert(t *testing.T) {
	b := newBox(t, true)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	_, err := alice.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{}))
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_NOT_STAGED")
	id, _ := alice.upload(t, bin(t, b.sign, b.enc, full(release.ChannelProduction)))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{})); err != nil {
		t.Fatal(err)
	}
	if b.init.activated != 1 || b.init.reboots != 1 {
		t.Fatal("apply activates and reboots")
	}
	if _, err := alice.upgrade().RevertUpdate(ctx, connect.NewRequest(&osadminv1.RevertUpdateRequest{})); err != nil {
		t.Fatal(err)
	}
	if b.init.rollbacks != 1 || b.init.reboots != 2 {
		t.Fatal("revert rolls back and reboots")
	}
	bob := b.browser()
	bob.signIn("bob")
	_, err = bob.upgrade().ApplyUpdate(ctx, connect.NewRequest(&osadminv1.ApplyUpdateRequest{}))
	symbolIn(t, err, connect.CodePermissionDenied, "ACCESS_FORBIDDEN")
}

func TestTheWindowAppliesOnce(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	open := b.clk.Now().Local().Add(-10 * time.Minute).Format("15:04")
	pol := &osadminv1.UpgradePolicy{Mode: "manual", WindowStart: open, WindowMinutes: 60}
	if _, err := alice.upgrade().SetUpgradePolicy(ctx, connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol})); err != nil {
		t.Fatal(err)
	}
	b.srv.UpgradeWindowTick(ctx)
	if b.init.activated != 0 {
		t.Fatal("nothing staged")
	}
	id, _ := alice.upload(t, bin(t, b.sign, b.enc, full(release.ChannelProduction)))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	b.srv.UpgradeWindowTick(ctx)
	if b.init.activated != 0 {
		t.Fatal("manual mode never applies in the window")
	}
	pol.Mode = "automatic"
	if _, err := alice.upgrade().SetUpgradePolicy(ctx, connect.NewRequest(&osadminv1.SetUpgradePolicyRequest{Policy: pol})); err != nil {
		t.Fatal(err)
	}
	b.srv.UpgradeWindowTick(ctx)
	b.srv.UpgradeWindowTick(ctx)
	if b.init.activated != 1 {
		t.Fatalf("applied %d times", b.init.activated)
	}
	if e := lastEntry(t, b.log, "upgrade.apply"); e.Actor != "window" || e.Outcome != "ok" {
		t.Fatalf("%+v", e)
	}
}

func TestTheBootedReleaseIsMarkedGoodOnceTheBoxIsHealthy(t *testing.T) {
	b := newBox(t, false)
	ctx := context.Background()
	if err := b.srv.MarkGood(ctx); err == nil || b.init.markedGood != 0 {
		t.Fatalf("before setup is done: %v, marked %d", err, b.init.markedGood)
	}
	if err := os.MkdirAll(filepath.Join(b.state, "setup"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.state, "setup", osadmin.DoneMarker), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	b.netd.down = true
	if err := b.srv.MarkGood(ctx); err == nil || b.init.markedGood != 0 {
		t.Fatalf("with netd down: %v, marked %d", err, b.init.markedGood)
	}
	b.netd.down = false
	if err := b.srv.MarkGood(ctx); err != nil || b.init.markedGood != 1 {
		t.Fatalf("healthy: %v, marked %d", err, b.init.markedGood)
	}
}

func TestMarkGoodWaitsOutAnApplyOrRevert(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	if err := os.MkdirAll(filepath.Join(b.state, "setup"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.state, "setup", osadmin.DoneMarker), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// A revert marks the running release bad and reboots; marking it good
	// before the reboot would undo the revert.
	if _, err := alice.upgrade().RevertUpdate(ctx, connect.NewRequest(&osadminv1.RevertUpdateRequest{})); err != nil {
		t.Fatal(err)
	}
	if err := b.srv.MarkGood(ctx); err == nil || b.init.markedGood != 0 {
		t.Fatalf("during a revert: %v, marked %d", err, b.init.markedGood)
	}
}
