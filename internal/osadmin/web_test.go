// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"connectrpc.com/connect"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/osadmin"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/webslots"
)

// webBox is a box with web slots and a watcher standing in for
// sneakers-osadmin, which serves the pages and records which.
type webBox struct {
	*box
	webDir, served string
	live           *webslots.Live
}

func newWebBox(t *testing.T) *webBox {
	t.Helper()
	wb := &webBox{webDir: filepath.Join(t.TempDir(), "web"), served: filepath.Join(t.TempDir(), "web-served.json")}
	wb.box = newBox(t, false, func(_ *box, o *osadmin.Options) {
		o.Upgrade.WebDir, o.Upgrade.WebServedFile, o.Upgrade.WebSwitchWait, o.Upgrade.BuiltinWebVersion = wb.webDir, wb.served, 3*time.Second, "0.1.0"
	})
	key, err := sigbundle.ParsePublicKey(wb.sign.PublicPEM)
	if err != nil {
		t.Fatal(err)
	}
	builtin := fstest.MapFS{"index.html": {Data: []byte("built-in")}}
	wb.live = webslots.NewLive(builtin, "0.1.0")
	w := &webslots.Watcher{Slots: webslots.Slots{Dir: wb.webDir}, Key: key, Channel: release.ChannelProduction, BaseOS: "0.1.0", Builtin: builtin, BuiltinVersion: "0.1.0", Live: wb.live, StatusFile: wb.served}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go w.Run(ctx, 20*time.Millisecond)
	return wb
}

// webBin is a Base Web .bin with signed pages for version.
func (wb *webBox) webBin(t *testing.T, h updatepkg.Header) []byte {
	t.Helper()
	dir := t.TempDir()
	pages := filepath.Join(dir, webslots.PagesDir)
	if err := os.MkdirAll(filepath.Join(pages, "assets"), 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"index.html": "<html>" + h.Version + "</html>", "assets/app.js": "app " + h.Version} {
		if err := os.WriteFile(filepath.Join(pages, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var need *updatepkg.Range
	if r, ok := h.Requires[updatepkg.UnitBaseOS]; ok {
		need = &r
	}
	m, err := webslots.WriteManifest(pages, h.Version, "", need)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{webslots.ManifestFile: m, webslots.SigFile: wb.sign.BlobBundle(t, m)} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var payload, ct, out bytes.Buffer
	if err := updatepkg.TarDir(dir, &payload); err != nil {
		t.Fatal(err)
	}
	h, err = updatepkg.Encrypt(&payload, h, wb.enc.Recipient(), &ct)
	if err != nil {
		t.Fatal(err)
	}
	hdr, _ := h.Marshal()
	if err := updatepkg.Seal(&out, hdr, wb.sign.BlobBundle(t, hdr), &ct); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func web(v string) updatepkg.Header {
	return updatepkg.Header{Unit: updatepkg.UnitBaseWeb, Version: v, Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelProduction}
}

func webStatus(t *testing.T, br *browser) *osadminv1.BaseWebStatus {
	t.Helper()
	g, err := br.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	return g.Msg.GetBaseWeb()
}

func applyWeb(b *box, br *browser) error {
	_, err := br.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: osadminv1.UpdateTarget_UPDATE_TARGET_BASE_WEB, TotpCode: b.code("alice")}))
	return err
}

func revertWeb(b *box, br *browser) error {
	_, err := br.upgrade().RevertUpdate(context.Background(), connect.NewRequest(&osadminv1.RevertUpdateRequest{Target: osadminv1.UpdateTarget_UPDATE_TARGET_BASE_WEB, TotpCode: b.code("alice")}))
	return err
}

// A Base Web stages into a web slot and applies with a fresh code and no
// reboot or maintenance; :8443 then serves it, and Revert goes back to the
// built-in pages.
func TestABaseWebAppliesWithoutAReboot(t *testing.T) {
	wb := newWebBox(t)
	alice := wb.browser()
	alice.signIn("alice")
	if st := webStatus(t, alice); st.GetSource() != webslots.SourceBuiltIn || st.GetRunningVersion() != "0.1.0" || st.GetCanRevert() {
		t.Fatalf("before: %v", st)
	}
	id, _ := alice.upload(t, wb.webBin(t, web("0.1.2")))
	res, err := alice.upgrade().StageUpdate(context.Background(), connect.NewRequest(&osadminv1.StageUpdateRequest{UploadId: id}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.GetPackage().GetTarget() != osadminv1.UpdateTarget_UPDATE_TARGET_BASE_WEB || res.Msg.GetSlot() != "a" || webStatus(t, alice).GetStagedVersion() != "0.1.2" {
		t.Fatalf("staged %v", res.Msg)
	}
	_, err = alice.upgrade().ApplyUpdate(context.Background(), connect.NewRequest(&osadminv1.ApplyUpdateRequest{Target: osadminv1.UpdateTarget_UPDATE_TARGET_BASE_WEB}))
	symbolIn(t, err, connect.CodeInvalidArgument, "ACCESS_CONFIRM")
	if err := applyWeb(wb.box, alice); err != nil {
		t.Fatal(err)
	}
	if st := webStatus(t, alice); st.GetSource() != webslots.SourceSlot || st.GetSlot() != "a" || st.GetRunningVersion() != "0.1.2" || !st.GetCanRevert() || st.GetRequiresBaseOs() != "0.1.0 to before 0.2.0" || !st.GetFits() {
		t.Fatalf("after: %v", st)
	}
	if wb.init.reboots != 0 || wb.init.activated != 0 || wb.srv.Maintenance() || wb.services.log() != nil {
		t.Fatal("a Base Web apply touched the box or the product")
	}
	g, _ := alice.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if h := g.Msg.GetHistory()[0]; h.GetTarget() != osadminv1.UpdateTarget_UPDATE_TARGET_BASE_WEB || h.GetAction() != "apply" || h.GetOutcome() != "ok" {
		t.Fatalf("history %v", h)
	}
	if p := g.Msg.GetUpgradeProgress(); p.GetInProgress() || p.GetFailed() || p.GetSteps()[len(p.GetSteps())-1].GetId() != "load" {
		t.Fatalf("progress %v", p)
	}
	if err := revertWeb(wb.box, alice); err != nil {
		t.Fatal(err)
	}
	if st := webStatus(t, alice); st.GetSource() != webslots.SourceBuiltIn || st.GetCanRevert() {
		t.Fatalf("after the revert: %v", st)
	}
	symbolIn(t, revertWeb(wb.box, alice), connect.CodeFailedPrecondition, "UPGRADE_NO_PREVIOUS")
}

// A Base Web that doesn't fit the running Base OS is refused at stage with
// the fix in words, nothing is written, and the upload is kept.
func TestABaseWebForAnotherBaseOSIsRefusedAndKept(t *testing.T) {
	wb := newWebBox(t)
	alice := wb.browser()
	alice.signIn("alice")
	h := web("0.2.0")
	id, _ := alice.upload(t, wb.webBin(t, h))
	err := stage(alice, id)
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_COMPAT")
	if !strings.Contains(err.Error(), "Base Web 0.2.0 needs Base OS 0.2.0 to before 0.3.0. This box runs Base OS 0.1.0. Install Base OS 0.2.x first") {
		t.Fatalf("%v", err)
	}
	if webStatus(t, alice).GetStagedVersion() != "" || wb.keyReads != 0 {
		t.Fatal("something was decrypted or staged")
	}
	g, _ := alice.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if g.Msg.GetHeldUpload().GetUploadId() != id {
		t.Fatalf("the upload isn't kept: %v", g.Msg.GetHeldUpload())
	}
}

// An apply whose pages :8443 won't load (changed on disk after the stage)
// puts the links back and fails the step; the old pages keep serving.
func TestABaseWebThatDoesntLoadPutsTheLinksBack(t *testing.T) {
	wb := newWebBox(t)
	alice := wb.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, wb.webBin(t, web("0.1.2")))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wb.webDir, "a", webslots.PagesDir, "index.html"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	symbolIn(t, applyWeb(wb.box, alice), connect.CodeFailedPrecondition, "UPGRADE_WEB_LOAD")
	st := webStatus(t, alice)
	if st.GetSource() != webslots.SourceBuiltIn || st.GetStagedVersion() != "0.1.2" || st.GetCurrentVersion() != "" {
		t.Fatalf("after a failed apply: %v", st)
	}
	g, _ := alice.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if p := g.Msg.GetUpgradeProgress(); !p.GetFailed() || p.GetCode() != "UPGRADE_WEB_LOAD" {
		t.Fatalf("progress %v", p)
	}
}

// Revert is refused when the previous Base Web doesn't fit the running
// Base OS.
func TestARevertToABaseWebThatDoesntFitIsRefused(t *testing.T) {
	wb := newWebBox(t)
	alice := wb.browser()
	alice.signIn("alice")
	old := web("0.1.2")
	old.Requires = map[updatepkg.Unit]updatepkg.Range{updatepkg.UnitBaseOS: {Min: "0.1.0", Before: "0.1.5"}}
	cur := web("0.1.3")
	cur.Requires = map[updatepkg.Unit]updatepkg.Range{updatepkg.UnitBaseOS: {Min: "0.1.0"}}
	for _, h := range []updatepkg.Header{old, cur} {
		id, _ := alice.upload(t, wb.webBin(t, h))
		if err := stage(alice, id); err != nil {
			t.Fatal(err)
		}
		if err := applyWeb(wb.box, alice); err != nil {
			t.Fatal(err)
		}
	}
	wb.init.mu.Lock()
	wb.init.running = "0.1.7"
	wb.init.mu.Unlock()
	err := revertWeb(wb.box, alice)
	symbolIn(t, err, connect.CodeFailedPrecondition, "UPGRADE_COMPAT")
	if st := webStatus(t, alice); st.GetCurrentVersion() != "0.1.3" {
		t.Fatalf("a refused revert moved the links: %v", st)
	}
}

// A unit of another key epoch is refused before anything is unpacked.
func TestAnUpdateOfAnotherEpochIsRefused(t *testing.T) {
	wb := newWebBox(t)
	alice := wb.browser()
	alice.signIn("alice")
	for _, h := range []updatepkg.Header{web("0.1.2"), {Unit: updatepkg.UnitBaseOS, Version: "0.2.0", Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelProduction}} {
		h.Epoch = 2
		var b []byte
		if h.Unit == updatepkg.UnitBaseWeb {
			b = wb.webBin(t, h)
		} else {
			b = bin(t, wb.sign, wb.enc, h)
		}
		id, _ := alice.upload(t, b)
		symbolIn(t, stage(alice, id), connect.CodeFailedPrecondition, "UPGRADE_EPOCH")
	}
	if wb.keyReads != 0 {
		t.Fatal("decrypted")
	}
}

// A staged Base OS whose built-in pages the installed Base Web doesn't fit
// says, before Apply, what the box serves after the reboot.
func TestAStagedBaseOSSaysWhichPagesServeAfterTheReboot(t *testing.T) {
	wb := newWebBox(t)
	alice := wb.browser()
	alice.signIn("alice")
	id, _ := alice.upload(t, wb.webBin(t, web("0.1.2")))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	if err := applyWeb(wb.box, alice); err != nil {
		t.Fatal(err)
	}
	id, _ = alice.upload(t, bin(t, wb.sign, wb.enc, full(release.ChannelProduction)))
	if err := stage(alice, id); err != nil {
		t.Fatal(err)
	}
	g, _ := alice.upgrade().GetUpgrades(context.Background(), connect.NewRequest(&osadminv1.GetUpgradesRequest{}))
	if n := g.Msg.GetBaseOsNote(); !strings.Contains(n, "serves the built-in pages of 0.2.0") || !strings.Contains(n, "0.1.0 to before 0.2.0") {
		t.Fatalf("note %q", n)
	}
}
