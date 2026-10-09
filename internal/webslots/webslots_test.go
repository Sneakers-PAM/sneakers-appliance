// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package webslots_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/release"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/sigbundle"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/testpki"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/updatepkg"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/webslots"
)

// payload writes a signed page set into dir, as a Base Web payload
// unpacks: pages/, web.yaml and web.yaml.sig.
func payload(t *testing.T, sign testpki.ECKey, dir, version string, need *updatepkg.Range, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, webslots.PagesDir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m, err := webslots.WriteManifest(filepath.Join(dir, webslots.PagesDir), version, "1a2b3c4", need)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, webslots.ManifestFile), m, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, webslots.SigFile), sign.BlobBundle(t, m), 0o600); err != nil {
		t.Fatal(err)
	}
}

func pages(version string) map[string]string {
	return map[string]string{"index.html": "<html>" + version + "</html>", "assets/app-" + version + ".js": "app " + version}
}

func header(version string) updatepkg.Header {
	return updatepkg.Header{Name: updatepkg.NameWeb, Unit: updatepkg.UnitBaseWeb, Version: version, Arch: "amd64", Kind: updatepkg.KindFull, Channel: release.ChannelLab}
}

func stageWeb(t *testing.T, sl webslots.Slots, sign testpki.ECKey, version string) error {
	t.Helper()
	key, err := sigbundle.ParsePublicKey(sign.PublicPEM)
	if err != nil {
		t.Fatal(err)
	}
	return sl.Stage(header(version), func(dir string) error { payload(t, sign, dir, version, nil, pages(version)); return nil }, key)
}

func TestStageApplyRevertAndUnstage(t *testing.T) {
	sign := testpki.ECDSA(t)
	sl := webslots.Slots{Dir: t.TempDir()}
	if err := stageWeb(t, sl, sign, "0.3.1"); err != nil {
		t.Fatal(err)
	}
	if st := sl.Status(); st.Staged != "0.3.1" || st.StagedSlot != "a" || st.Current != "" {
		t.Fatalf("%+v", st)
	}
	v, _, err := sl.Apply()
	if err != nil || v != "0.3.1" {
		t.Fatalf("%s %v", v, err)
	}
	if err := stageWeb(t, sl, sign, "0.3.2"); err != nil {
		t.Fatal(err)
	}
	if v, _, err = sl.Apply(); err != nil || v != "0.3.2" {
		t.Fatalf("%s %v", v, err)
	}
	if st := sl.Status(); st.Current != "0.3.2" || st.CurrentSlot != "b" || st.Previous != "0.3.1" || st.PreviousSlot != "a" {
		t.Fatalf("%+v", st)
	}
	if v, _, err = sl.Revert(); err != nil || v != "0.3.1" {
		t.Fatalf("revert %s %v", v, err)
	}
	if st := sl.Status(); st.Current != "0.3.1" || st.Previous != "0.3.2" {
		t.Fatalf("%+v", st)
	}
	if err := stageWeb(t, sl, sign, "0.3.3"); err != nil {
		t.Fatal(err)
	}
	if v, err := sl.Unstage(); err != nil || v != "0.3.3" || sl.Status().Staged != "" {
		t.Fatalf("unstage %s %v", v, err)
	}
	if _, err := sl.Unstage(); !codes.Is(err, codes.UpgradeNotStaged) {
		t.Fatalf("nothing staged: %v", err)
	}
}

// A revert with no previous slot goes back to the built-in pages; the undo
// puts the links back for a switch whose pages don't load.
func TestARevertWithNoPreviousGoesToTheBuiltInPages(t *testing.T) {
	sign := testpki.ECDSA(t)
	sl := webslots.Slots{Dir: t.TempDir()}
	if _, _, err := sl.Revert(); !codes.Is(err, codes.UpgradeNoPrevious) {
		t.Fatalf("nothing installed: %v", err)
	}
	if err := stageWeb(t, sl, sign, "0.3.1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sl.Apply(); err != nil {
		t.Fatal(err)
	}
	v, undo, err := sl.Revert()
	if err != nil || v != "" || sl.Status().Current != "" || sl.CurrentDir() != "" {
		t.Fatalf("%q %v %+v", v, err, sl.Status())
	}
	if err := undo(); err != nil || sl.Status().Current != "0.3.1" {
		t.Fatalf("undo: %v %+v", err, sl.Status())
	}
}

// Each way a slot can fail its checks ends with UPGRADE_WEB_LOAD, and the
// stage leaves nothing staged.
func TestALoadRefusesWhatDoesntCheckOut(t *testing.T) {
	sign := testpki.ECDSA(t)
	key, _ := sigbundle.ParsePublicKey(sign.PublicPEM)
	other := testpki.ECDSA(t)
	for name, spoil := range map[string]func(dir string){
		"a changed file": func(dir string) { write(t, filepath.Join(dir, "pages", "index.html"), "<html>changed</html>") },
		"an extra file":  func(dir string) { write(t, filepath.Join(dir, "pages", "extra.js"), "x") },
		"a missing file": func(dir string) { _ = os.Remove(filepath.Join(dir, "pages", "assets", "app-0.3.1.js")) },
		"a link":         func(dir string) { _ = os.Symlink("/etc/passwd", filepath.Join(dir, "pages", "passwd")) },
		"another key's sig": func(dir string) {
			m, _ := os.ReadFile(filepath.Join(dir, "web.yaml"))
			write(t, filepath.Join(dir, "web.yaml.sig"), string(other.BlobBundle(t, m)))
		},
		"a changed manifest": func(dir string) {
			m, _ := os.ReadFile(filepath.Join(dir, "web.yaml"))
			write(t, filepath.Join(dir, "web.yaml"), strings.Replace(string(m), "0.3.1", "0.3.9", 1))
		},
		"no signature":   func(dir string) { _ = os.Remove(filepath.Join(dir, "web.yaml.sig")) },
		"a path outside": func(dir string) { resign(t, sign, dir, "../escape.js") },
	} {
		sl := webslots.Slots{Dir: t.TempDir()}
		err := sl.Stage(header("0.3.1"), func(dir string) error {
			payload(t, sign, dir, "0.3.1", nil, pages("0.3.1"))
			spoil(dir)
			return nil
		}, key)
		if !codes.Is(err, codes.UpgradeWebLoad) {
			t.Errorf("%s: want UPGRADE_WEB_LOAD, got %v", name, err)
		}
		if sl.Status().Staged != "" {
			t.Errorf("%s: staged anyway", name)
		}
	}
	sl := webslots.Slots{Dir: t.TempDir()}
	err := sl.Stage(header("0.3.2"), func(dir string) error { payload(t, sign, dir, "0.3.1", nil, pages("0.3.1")); return nil }, key)
	if !codes.Is(err, codes.UpgradeWebLoad) {
		t.Fatalf("pages of another version than the header: %v", err)
	}
}

func write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// resign lists an extra path in the manifest and signs it again.
func resign(t *testing.T, sign testpki.ECKey, dir, extra string) {
	t.Helper()
	m, _ := os.ReadFile(filepath.Join(dir, webslots.ManifestFile)) // #nosec G304 -- test-only
	m = []byte(strings.Replace(string(m), "files:\n", "files:\n    - path: "+extra+"\n      size: 1\n      sha256: "+strings.Repeat("0", 64)+"\n", 1))
	write(t, filepath.Join(dir, webslots.ManifestFile), string(m))
	write(t, filepath.Join(dir, webslots.SigFile), string(sign.BlobBundle(t, m)))
}

func readFS(t *testing.T, f fs.FS, name string) string {
	t.Helper()
	b, err := fs.ReadFile(f, name)
	if err != nil {
		return ""
	}
	return string(b)
}

// The watcher serves the current slot when it checks out and fits the
// running Base OS, the built-in pages otherwise, and says which and why;
// the set it replaced still answers for files the new one lacks.
func TestTheWatcherServesTheCurrentSlotOrTheBuiltInPages(t *testing.T) {
	sign := testpki.ECDSA(t)
	key, _ := sigbundle.ParsePublicKey(sign.PublicPEM)
	sl := webslots.Slots{Dir: t.TempDir()}
	builtin := fstest.MapFS{"index.html": {Data: []byte("built-in")}, "assets/app-builtin.js": {Data: []byte("old app")}}
	status := filepath.Join(t.TempDir(), "web-served.json")
	newWatcher := func(base string) *webslots.Watcher {
		return &webslots.Watcher{Slots: sl, Key: key, Channel: release.ChannelProduction, BaseOS: base, Builtin: builtin, BuiltinVersion: base,
			Live: webslots.NewLive(builtin, base), StatusFile: status, Now: func() time.Time { return time.Unix(0, 0) }}
	}
	w := newWatcher("0.3.0")
	w.Sync()
	if s := w.Live.Served(); s.Source != webslots.SourceBuiltIn || s.Version != "0.3.0" || s.Reason == "" || readFS(t, w.Live, "index.html") != "built-in" {
		t.Fatalf("no Base Web: %+v", s)
	}
	if err := stageWeb(t, sl, sign, "0.3.1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sl.Apply(); err != nil {
		t.Fatal(err)
	}
	w.Sync()
	if s := w.Live.Served(); s.Source != webslots.SourceSlot || s.Slot != "a" || s.Version != "0.3.1" || readFS(t, w.Live, "index.html") != "<html>0.3.1</html>" {
		t.Fatalf("after the switch: %+v", s)
	}
	if readFS(t, w.Live, "assets/app-builtin.js") != "old app" {
		t.Fatal("an open page's asset from the set before isn't answered")
	}
	if got, err := webslots.ReadServed(status); err != nil || got.Version != "0.3.1" || got.WantedVersion != "0.3.1" {
		t.Fatalf("status file %+v %v", got, err)
	}
	// What's on disk later doesn't change what's served until the next
	// load, which checks again: a restart then serves the built-in pages.
	write(t, filepath.Join(sl.CurrentDir(), "pages", "index.html"), "<html>tampered</html>")
	w.Sync()
	if readFS(t, w.Live, "index.html") != "<html>0.3.1</html>" {
		t.Fatal("a changed file on disk was served")
	}
	restarted := newWatcher("0.3.0")
	restarted.Sync()
	if s := restarted.Live.Served(); s.Source != webslots.SourceBuiltIn || !strings.Contains(s.Reason, "UPGRADE_WEB_LOAD") || s.WantedVersion != "0.3.1" {
		t.Fatalf("a tampered slot at start: %+v", s)
	}
	// Pages that don't fit the running Base OS aren't served either.
	if err := stageWeb(t, sl, sign, "0.3.2"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sl.Apply(); err != nil {
		t.Fatal(err)
	}
	other := newWatcher("0.4.0")
	other.Sync()
	if s := other.Live.Served(); s.Source != webslots.SourceBuiltIn || !strings.Contains(s.Reason, "needs Base OS 0.3.0 to before 0.4.0") {
		t.Fatalf("a Base Web for another Base OS: %+v", s)
	}
}
