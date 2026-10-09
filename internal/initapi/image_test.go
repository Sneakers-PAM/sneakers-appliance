// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package initapi_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/imageupgrade"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

type espDir string

func (e espDir) List(rel string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(string(e), rel))
	if os.IsNotExist(err) {
		return nil, nil
	}
	var out []string
	for _, x := range ents {
		out = append(out, x.Name())
	}
	return out, err
}

func (e espDir) WriteFile(rel string, r io.Reader) error {
	p := filepath.Join(string(e), rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

func (e espDir) Rename(a, b string) error {
	return os.Rename(filepath.Join(string(e), a), filepath.Join(string(e), b))
}

func (e espDir) Remove(rel string) error { return os.Remove(filepath.Join(string(e), rel)) }

func (e espDir) Open(rel string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(string(e), rel)) // #nosec G304 -- test-only
}

type discardSlots struct{}

func (discardSlots) WriteInactive(_ context.Context, r io.Reader, _ int64, _ string) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

type noSeal struct{}

func (noSeal) SealForImage(context.Context, string, []byte) error { return nil }
func (noSeal) Prune(context.Context, []string) error              { return nil }

type keptSeal struct {
	noSeal
	kept []string
}

func (k *keptSeal) Prune(_ context.Context, keep []string) error { k.kept = keep; return nil }

// serveImages serves a stager running an older lab build, as a box on the
// previous build would be.
func serveImages(t *testing.T, images initapi.Images) initv1connect.ImageServiceClient {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "init.sock")
	srv, err := initapi.Listen(sock, initapi.Options{Allow: func(uint32) bool { return true }, Images: images})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	return initv1connect.NewImageServiceClient(client(sock), "http://init.sock")
}

func TestImageServiceStagesAndReportsThroughInit(t *testing.T) {
	dir, pins := fixtures.Build(t, fixtures.Options{})
	const running = "0.0.0-lab.20261007e-gabc1234"
	esp := espDir(t.TempDir())
	if err := esp.WriteFile(filepath.Join(imageupgrade.UKIDir, imageupgrade.GoodName(running)), strings.NewReader("running")); err != nil {
		t.Fatal(err)
	}
	s := &imageupgrade.Stager{ESP: esp, Slots: discardSlots{}, Sealer: noSeal{}, Pins: pins, Running: running, InitVersion: running, WorkDir: t.TempDir()}
	c := serveImages(t, s)
	ctx := context.Background()

	st, err := c.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{}))
	if err != nil || st.Msg.GetRunningVersion() != running || st.Msg.GetStagedVersion() != "" {
		t.Fatalf("status before staging: %v %v", st, err)
	}
	if _, err := c.Activate(ctx, connect.NewRequest(&initv1.ActivateRequest{})); err == nil || !strings.Contains(err.Error(), "UPGRADE_NOT_STAGED") {
		t.Fatalf("activate with nothing staged: %v", err)
	}
	got, err := c.Stage(ctx, connect.NewRequest(&initv1.StageRequest{Reference: dir}))
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if got.Msg.GetVersion() != fixtures.Version {
		t.Fatalf("staged %q", got.Msg.GetVersion())
	}
	st, err = c.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{}))
	if err != nil || st.Msg.GetStagedVersion() != fixtures.Version {
		t.Fatalf("status after staging: %v %v", st, err)
	}
	if _, err := c.Activate(ctx, connect.NewRequest(&initv1.ActivateRequest{})); err != nil {
		t.Fatalf("activate: %v", err)
	}
	// The box boots the new release, an admin reverts, and it boots the old one again.
	s.Running = fixtures.Version
	st, err = c.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{}))
	if err != nil || st.Msg.GetPreviousVersion() != running || st.Msg.GetStagedVersion() != "" {
		t.Fatalf("status on the new release: %v %v", st, err)
	}
	if _, err := c.Rollback(ctx, connect.NewRequest(&initv1.RollbackRequest{By: "alice"})); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	s.Running = running
	st, err = c.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{}))
	if err != nil || st.Msg.GetFailedVersion() != "" || st.Msg.GetRevertedVersion() != fixtures.Version || st.Msg.GetRevertedBy() != "alice" || st.Msg.GetRevertedAt() == nil || st.Msg.GetPreviousVersion() != "" {
		t.Fatalf("status after a revert: %v %v", st, err)
	}
}

func TestImageServiceIsUnimplementedWithoutImages(t *testing.T) {
	c := serveImages(t, nil)
	_, err := c.Status(context.Background(), connect.NewRequest(&initv1.ImageServiceStatusRequest{}))
	if connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("got %v", err)
	}
}

func TestImageServiceMarksTheRunningReleaseGood(t *testing.T) {
	const running = "0.0.0-lab.20261007e1-gabc1234"
	esp := espDir(t.TempDir())
	for name, body := range map[string]string{
		imageupgrade.EntryName(running, 2, 1):                 "red",
		imageupgrade.GoodName("0.0.0-lab.20261007e-gabc1234"): "blue",
	} {
		if err := esp.WriteFile(filepath.Join(imageupgrade.UKIDir, name), strings.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	}
	seal := &keptSeal{}
	c := serveImages(t, &imageupgrade.Stager{ESP: esp, Slots: discardSlots{}, Sealer: seal, Running: running, WorkDir: t.TempDir()})
	if _, err := c.MarkGood(context.Background(), connect.NewRequest(&initv1.MarkGoodRequest{})); err != nil {
		t.Fatalf("mark good: %v", err)
	}
	names, _ := esp.List(imageupgrade.UKIDir)
	slices.Sort(names)
	if want := []string{imageupgrade.GoodName("0.0.0-lab.20261007e-gabc1234"), imageupgrade.GoodName(running)}; !slices.Equal(names, want) {
		t.Fatalf("entries %v; want %v", names, want)
	}
	// Both UKIs stay bootable: neither one's sealed copy is pruned.
	if len(seal.kept) != 3 {
		t.Fatalf("kept %v; want both UKIs and the install copy", seal.kept)
	}
}

func TestImageStageNamesTheReleasesItRemoved(t *testing.T) {
	dir, pins := fixtures.Build(t, fixtures.Options{})
	const previous, running = "0.0.8", "0.0.9"
	esp := espDir(t.TempDir())
	for _, v := range []string{previous, running} {
		if err := esp.WriteFile(filepath.Join(imageupgrade.UKIDir, imageupgrade.GoodName(v)), strings.NewReader(v)); err != nil {
			t.Fatal(err)
		}
	}
	c := serveImages(t, &imageupgrade.Stager{ESP: esp, Slots: discardSlots{}, Sealer: noSeal{}, Pins: pins, Running: running, WorkDir: t.TempDir()})
	got, err := c.Stage(context.Background(), connect.NewRequest(&initv1.StageRequest{Reference: dir}))
	if err != nil {
		t.Fatal(err)
	}
	if r := got.Msg.GetRemovedVersions(); len(r) != 1 || r[0] != previous {
		t.Fatalf("removed %v; want %s", r, previous)
	}
}

func TestImageStatusNamesWhatTheNextStageRemoves(t *testing.T) {
	const previous, running = "0.0.8", "0.0.9"
	esp := espDir(t.TempDir())
	for _, v := range []string{previous, running} {
		if err := esp.WriteFile(filepath.Join(imageupgrade.UKIDir, imageupgrade.GoodName(v)), strings.NewReader(v)); err != nil {
			t.Fatal(err)
		}
	}
	c := serveImages(t, &imageupgrade.Stager{ESP: esp, Slots: discardSlots{}, Sealer: noSeal{}, Running: running, WorkDir: t.TempDir()})
	st, err := c.Status(context.Background(), connect.NewRequest(&initv1.ImageServiceStatusRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if r := st.Msg.GetNextStageRemoves(); len(r) != 1 || r[0] != previous {
		t.Fatalf("next stage removes %v; want %s", r, previous)
	}
}

// heldSlots reads one chunk of the root image, says so, and waits to be
// let go before reading the rest.
type heldSlots struct {
	read, release chan struct{}
}

func (h heldSlots) WriteInactive(_ context.Context, r io.Reader, _ int64, _ string) error {
	if _, err := io.CopyN(io.Discard, r, 1); err != nil {
		return err
	}
	close(h.read)
	<-h.release
	_, err := io.Copy(io.Discard, r)
	return err
}

// Status answers while a Stage writes the slot, with how much it wrote.
func TestImageStatusReportsAStageWriting(t *testing.T) {
	dir, pins := fixtures.Build(t, fixtures.Options{})
	const running = "0.0.0-lab.20261007e-gabc1234"
	esp := espDir(t.TempDir())
	if err := esp.WriteFile(filepath.Join(imageupgrade.UKIDir, imageupgrade.GoodName(running)), strings.NewReader("running")); err != nil {
		t.Fatal(err)
	}
	held := heldSlots{read: make(chan struct{}), release: make(chan struct{})}
	s := &imageupgrade.Stager{ESP: esp, Slots: held, Sealer: noSeal{}, Pins: pins, Running: running, InitVersion: running, WorkDir: t.TempDir()}
	c := serveImages(t, s)
	ctx := context.Background()
	staged := make(chan error, 1)
	go func() {
		_, err := c.Stage(ctx, connect.NewRequest(&initv1.StageRequest{Reference: dir}))
		staged <- err
	}()
	<-held.read
	st, err := c.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{}))
	close(held.release)
	if err != nil {
		t.Fatal(err)
	}
	if w, total := st.Msg.GetStageWrittenBytes(), st.Msg.GetStageTotalBytes(); w <= 0 || total <= 0 || w > total {
		t.Fatalf("while writing: %d of %d", w, total)
	}
	if err := <-staged; err != nil {
		t.Fatal(err)
	}
	st, err = c.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{}))
	if err != nil || st.Msg.GetStageTotalBytes() != 0 {
		t.Fatalf("after the stage: %v %v", st, err)
	}
}

func TestImageServiceUnstagesThroughInit(t *testing.T) {
	dir, pins := fixtures.Build(t, fixtures.Options{})
	const running = "0.0.0-lab.20261007e-gabc1234"
	esp := espDir(t.TempDir())
	if err := esp.WriteFile(filepath.Join(imageupgrade.UKIDir, imageupgrade.GoodName(running)), strings.NewReader("running")); err != nil {
		t.Fatal(err)
	}
	s := &imageupgrade.Stager{ESP: esp, Slots: discardSlots{}, Sealer: noSeal{}, Pins: pins, Running: running, InitVersion: running, WorkDir: t.TempDir()}
	c := serveImages(t, s)
	ctx := context.Background()
	if _, err := c.Unstage(ctx, connect.NewRequest(&initv1.UnstageRequest{})); err == nil || !strings.Contains(err.Error(), "UPGRADE_NOT_STAGED") {
		t.Fatalf("unstage with nothing staged: %v", err)
	}
	if _, err := c.Stage(ctx, connect.NewRequest(&initv1.StageRequest{Reference: dir})); err != nil {
		t.Fatal(err)
	}
	got, err := c.Unstage(ctx, connect.NewRequest(&initv1.UnstageRequest{}))
	if err != nil || got.Msg.GetVersion() != fixtures.Version {
		t.Fatalf("unstage: %v %v", got, err)
	}
	st, err := c.Status(ctx, connect.NewRequest(&initv1.ImageServiceStatusRequest{}))
	if err != nil || st.Msg.GetStagedVersion() != "" {
		t.Fatalf("status after unstaging: %v %v", st, err)
	}
}
