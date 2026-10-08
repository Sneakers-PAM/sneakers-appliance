// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package imageupgrade_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/imageupgrade"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

var ctx = context.Background()

func TestBootCounterNames(t *testing.T) {
	if got := imageupgrade.EntryName("0.2.0", 3, 0); got != "sneakers-0.2.0+3-0.efi" {
		t.Fatal(got)
	}
	for name, want := range map[string]imageupgrade.Entry{
		"sneakers-0.2.0+1-2.efi":      {Name: "sneakers-0.2.0+1-2.efi", Version: "0.2.0", Counted: true, Left: 1, Done: 2},
		"sneakers-0.2.0.efi":          {Name: "sneakers-0.2.0.efi", Version: "0.2.0"},
		"sneakers-0.3.0-rc.1+3.efi":   {Name: "sneakers-0.3.0-rc.1+3.efi", Version: "0.3.0-rc.1", Counted: true, Left: 3},
		"sneakers-0.3.0-rc.1+0-3.efi": {Name: "sneakers-0.3.0-rc.1+0-3.efi", Version: "0.3.0-rc.1", Counted: true, Left: 0, Done: 3},
	} {
		got, ok := imageupgrade.ParseEntry(name)
		if !ok || got != want {
			t.Errorf("%s: %+v %v", name, got, ok)
		}
	}
	for _, bad := range []string{"BOOTX64.EFI", "sneakers.efi", "other-0.1.0.efi"} {
		if _, ok := imageupgrade.ParseEntry(bad); ok {
			t.Errorf("%s parsed", bad)
		}
	}
}

// dirESP is the ESP in a directory.
type dirESP struct{ dir string }

func (e dirESP) List(rel string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(e.dir, rel))
	if os.IsNotExist(err) {
		return nil, nil
	}
	var out []string
	for _, x := range ents {
		out = append(out, x.Name())
	}
	sort.Strings(out)
	return out, err
}
func (e dirESP) WriteFile(rel string, r io.Reader) error {
	p := filepath.Join(e.dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}
func (e dirESP) Rename(a, b string) error {
	return os.Rename(filepath.Join(e.dir, a), filepath.Join(e.dir, b))
}
func (e dirESP) Remove(rel string) error { return os.Remove(filepath.Join(e.dir, rel)) }
func (e dirESP) Open(rel string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(e.dir, rel)) // #nosec G304 -- test-only
}

type fakeSlots struct {
	written  int64
	partUUID string
}

func (s *fakeSlots) WriteInactive(_ context.Context, r io.Reader, _ int64, guid string) error {
	n, err := io.Copy(io.Discard, r)
	s.written, s.partUUID = n, guid
	return err
}

type fakeSealer struct {
	sealed []string
	kept   []string
	order  *[]string
}

func (f *fakeSealer) SealForImage(_ context.Context, sha string, _ []byte) error {
	f.sealed = append(f.sealed, sha)
	*f.order = append(*f.order, "seal")
	return nil
}
func (f *fakeSealer) Prune(_ context.Context, keep []string) error { f.kept = keep; return nil }

type orderESP struct {
	dirESP
	order *[]string
}

func (e orderESP) WriteFile(rel string, r io.Reader) error {
	*e.order = append(*e.order, "esp "+filepath.Base(rel))
	return e.dirESP.WriteFile(rel, r)
}

func stager(t *testing.T, running string) (*imageupgrade.Stager, string, *fakeSlots, *fakeSealer, *[]string) {
	t.Helper()
	dir, pins := fixtures.Build(t, fixtures.Options{})
	esp := t.TempDir()
	order := &[]string{}
	slots, sealer := &fakeSlots{}, &fakeSealer{order: order}
	if running != "" {
		if err := os.MkdirAll(filepath.Join(esp, imageupgrade.UKIDir), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(esp, imageupgrade.UKIDir, imageupgrade.GoodName(running)), []byte("running"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &imageupgrade.Stager{ESP: orderESP{dirESP{esp}, order}, Slots: slots, Sealer: sealer, Pins: pins, Running: running, InitVersion: fixtures.Version, WorkDir: t.TempDir()}, dir, slots, sealer, order
}

func TestStageWritesSlotThenSealsThenEntry(t *testing.T) {
	s, dir, slots, sealer, order := stager(t, "0.0.9")
	ver, err := s.Stage(ctx, verify.LocalLayout(dir), "amd64")
	if err != nil || ver != fixtures.Version {
		t.Fatalf("%s %v", ver, err)
	}
	if slots.written == 0 || slots.partUUID == "" || len(sealer.sealed) != 1 {
		t.Fatalf("slot %+v sealed %v", slots, sealer.sealed)
	}
	if len(*order) != 2 || (*order)[0] != "seal" || (*order)[1] != "esp "+imageupgrade.EntryName(fixtures.Version, 3, 0) {
		t.Fatalf("order %v: the sealed copy must exist before the entry the firmware boots", *order)
	}
	st, _ := s.Status()
	if st.Staged != fixtures.Version || st.Running != "0.0.9" {
		t.Fatalf("status %+v", st)
	}
}

func TestStageRefusesDowngradeAndSameVersion(t *testing.T) {
	for _, running := range []string{"0.2.0", fixtures.Version} {
		s, dir, slots, _, order := stager(t, running)
		if _, err := s.Stage(ctx, verify.LocalLayout(dir), "amd64"); !codes.Is(err, codes.UpgradeDowngrade) {
			t.Fatalf("running %s: got %v", running, err)
		}
		if slots.written != 0 || len(*order) != 0 {
			t.Fatal("a refused release wrote something")
		}
	}
}

func TestStageRefusesAnUnsignedRelease(t *testing.T) {
	s, _, slots, _, order := stager(t, "0.0.9")
	dir, _ := fixtures.Build(t, fixtures.Options{Mutate: fixtures.DropSignature})
	if _, err := s.Stage(ctx, verify.LocalLayout(dir), "amd64"); !codes.Is(err, codes.KitSigMissing) {
		t.Fatalf("got %v", err)
	}
	if slots.written != 0 || len(*order) != 0 {
		t.Fatal("an unsigned release wrote something")
	}
}

func TestMarkGoodRollbackAndRevertedStatus(t *testing.T) {
	s, dir, _, sealer, _ := stager(t, "0.0.9")
	if _, err := s.Stage(ctx, verify.LocalLayout(dir), "amd64"); err != nil {
		t.Fatal(err)
	}
	// Boot into it: the box now runs the new release.
	s.Running = fixtures.Version
	if err := s.MarkGood(ctx, []string{"keep"}); err != nil {
		t.Fatal(err)
	}
	names, _ := s.ESP.List(imageupgrade.UKIDir)
	if len(names) != 2 || names[1] != imageupgrade.GoodName(fixtures.Version) {
		t.Fatalf("entries %v", names)
	}
	if len(sealer.kept) != 1 {
		t.Fatal("MarkGood prunes sealed copies")
	}
	at := time.Date(2026, 10, 8, 14, 5, 0, 0, time.UTC)
	if err := s.Rollback("alice", at); err != nil {
		t.Fatal(err)
	}
	names, _ = s.ESP.List(imageupgrade.UKIDir)
	e, _ := imageupgrade.ParseEntry(names[1])
	if !e.Bad() || e.Version != fixtures.Version {
		t.Fatalf("after rollback: %v", names)
	}
	// Back on the old release, the new one shows as reverted, not failed.
	s.Running = "0.0.9"
	st, _ := s.Status()
	if st.Failed != "" || st.Reverted.Version != fixtures.Version || st.Reverted.By != "alice" || !st.Reverted.At.Equal(at) {
		t.Fatalf("status %+v", st)
	}
	// Staging again forgets the revert.
	if _, err := s.Stage(ctx, verify.LocalLayout(dir), "amd64"); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Status(); st.Reverted.Version != "" || st.Staged != fixtures.Version {
		t.Fatalf("after a new stage: %+v", st)
	}
}

// A release that used up its boot tries without a Rollback is a failure.
func TestABootCountingFallbackIsFailed(t *testing.T) {
	s, dir, _, _, _ := stager(t, "0.0.9")
	if _, err := s.Stage(ctx, verify.LocalLayout(dir), "amd64"); err != nil {
		t.Fatal(err)
	}
	if err := s.ESP.Rename(path.Join(imageupgrade.UKIDir, imageupgrade.EntryName(fixtures.Version, imageupgrade.Tries, 0)), path.Join(imageupgrade.UKIDir, imageupgrade.EntryName(fixtures.Version, 0, imageupgrade.Tries))); err != nil {
		t.Fatal(err)
	}
	st, _ := s.Status()
	if st.Failed != fixtures.Version || st.Reverted.Version != "" {
		t.Fatalf("status %+v", st)
	}
}

func TestRollbackWithoutAPreviousRelease(t *testing.T) {
	s, _, _, _, _ := stager(t, "0.0.9")
	if err := s.Rollback("alice", time.Now()); !codes.Is(err, codes.UpgradeNoPrevious) {
		t.Fatalf("got %v", err)
	}
}

func TestStageOnAnOlderLabInit(t *testing.T) {
	s, dir, _, _, _ := stager(t, "0.0.0-lab.20261007e-gabc1234")
	s.InitVersion = "0.0.0-lab.20261007e-gabc1234"
	if _, err := s.Stage(ctx, verify.LocalLayout(dir), "amd64"); err != nil {
		t.Fatalf("a newer release must stage on the previous build's init: %v", err)
	}
}

func TestKeptNamesEveryUKIOnTheESPAndTheInstallCopy(t *testing.T) {
	s, dir, _, _, _ := stager(t, "0.0.9")
	if _, err := s.Stage(ctx, verify.LocalLayout(dir), "amd64"); err != nil {
		t.Fatal(err)
	}
	names, _ := s.ESP.List(imageupgrade.UKIDir)
	want := map[string]bool{"": true}
	for _, n := range names {
		f, err := s.ESP.Open(filepath.Join(imageupgrade.UKIDir, n))
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.New()
		_, _ = io.Copy(h, f)
		_ = f.Close()
		want[hex.EncodeToString(h.Sum(nil))] = true
	}
	kept, err := s.Kept()
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 3 || len(want) != 3 {
		t.Fatalf("kept %v; want the running and the staged UKI and the install copy", kept)
	}
	for _, k := range kept {
		if !want[k] {
			t.Fatalf("kept %v; want %v", kept, want)
		}
	}
}

func TestMarkGoodLeavesAnUncountedEntryAlone(t *testing.T) {
	s, _, _, _, _ := stager(t, "0.0.9")
	if err := s.MarkGood(ctx, []string{""}); err != nil {
		t.Fatal(err)
	}
	names, _ := s.ESP.List(imageupgrade.UKIDir)
	if len(names) != 1 || names[0] != imageupgrade.GoodName("0.0.9") {
		t.Fatalf("entries %v", names)
	}
}
