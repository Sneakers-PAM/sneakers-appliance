// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package backupset

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age" // scrub:allow=fqdn -- a Go module path
	"filippo.io/age/agessh" // scrub:allow=fqdn -- a Go module path
	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/productspec"
)

type fakeEngine struct {
	t       *testing.T
	store   string
	lsn     string
	base    func()
	bases   int
	failing string
	points  []string
	keys    map[string]string
}

func (f *fakeEngine) RestorePoint(_ context.Context, _ productspec.Backups, p string) (string, uint32, error) {
	f.points = append(f.points, p)
	return f.lsn, 1, nil
}

func (f *fakeEngine) RequestBase(context.Context, productspec.Backups) error {
	f.bases++
	if f.base != nil {
		f.base()
	}
	return nil
}

func (f *fakeEngine) Annotations(context.Context, productspec.Backups) (map[string]string, error) {
	return map[string]string{"failure": f.failing}, nil
}

func (f *fakeEngine) KeyDigest(_ context.Context, k productspec.EscrowKey) (string, error) {
	if d, ok := f.keys[k.Name]; ok {
		return d, nil
	}
	return "digest-of-" + k.Name, nil
}

// testBackups is a declaration with its directories under the test's own.
type fixture struct {
	spec productspec.Spec
	b    productspec.Backups
	m    *Manager
	e    *fakeEngine
	logs []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := filepath.Join(t.TempDir(), "backup")
	s := productspec.Spec{Escrow: []productspec.EscrowKey{{Name: "root-key", Secret: "app/keys", Key: "ROOT"}}}
	b := productspec.Backups{Dir: "postgres", Store: "walg", Mount: "/backup", Status: productspec.BackupStatus{Failure: "failure"}}
	b.Root = root
	s.Backups = &b
	e := &fakeEngine{t: t, store: b.StoreHostDir(), lsn: "0/4000028"}
	f := &fixture{spec: s, b: b, e: e}
	f.m = &Manager{Spec: func() (productspec.Spec, error) { return s, nil }, Engine: e, Every: time.Millisecond,
		Audit: func(a string, d map[string]string) { f.logs = append(f.logs, a+" "+d["set"]) }}
	return f
}

func (f *fixture) archive(t *testing.T) {
	t.Helper()
	writeStore(t, f.b.StoreHostDir(),
		"basebackups_005/base_000000010000000000000002"+sentinelSuffix,
		"basebackups_005/base_000000010000000000000002/tar_partitions/part_001.tar.lz4",
		"wal_005/000000010000000000000002.00000058.backup.lz4",
		"wal_005/000000010000000000000002.lz4",
		"wal_005/000000010000000000000003.lz4",
		"wal_005/000000010000000000000004.lz4",
		"wal_005/000000010000000000000005.lz4",
		"wal_005/00000002.history.lz4",
	)
}

func TestASetIsTheBaseAndTheWALUpToThePoint(t *testing.T) {
	f := newFixture(t)
	f.archive(t)
	mf, err := f.m.Create(context.Background(), "before-change")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(mf.Point, "before-change-") || mf.Keys["root-key"] != "digest-of-root-key" || mf.Base != "base_000000010000000000000002" {
		t.Fatalf("manifest = %+v", mf)
	}
	store := filepath.Join(f.b.SetsHostDir(), "before-change", "store")
	for _, want := range []string{
		"basebackups_005/base_000000010000000000000002" + sentinelSuffix,
		"basebackups_005/base_000000010000000000000002/tar_partitions/part_001.tar.lz4",
		"wal_005/000000010000000000000002.lz4", "wal_005/000000010000000000000004.lz4",
		"wal_005/000000010000000000000002.00000058.backup.lz4", "wal_005/00000002.history.lz4",
	} {
		if _, err := os.Stat(filepath.Join(store, want)); err != nil {
			t.Errorf("the set lacks %s", want)
		}
	}
	if _, err := os.Stat(filepath.Join(store, "wal_005/000000010000000000000005.lz4")); err == nil {
		t.Error("the set holds WAL past its point")
	}
	// A hard link costs nothing, and survives the archive's own retention.
	if err := os.RemoveAll(f.b.StoreHostDir()); err != nil {
		t.Fatal(err)
	}
	if err := Verify(f.b, mf); err != nil {
		t.Fatalf("the set didn't outlive its archive: %v", err)
	}
	list, err := f.m.List()
	if err != nil || len(list) != 1 || list[0].Name != "before-change" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if len(f.logs) != 1 || f.logs[0] != "product.backup.create before-change" {
		t.Fatalf("audit = %v", f.logs)
	}
}

func TestVerifyFindsADamagedSet(t *testing.T) {
	f := newFixture(t)
	f.archive(t)
	mf, err := f.m.Create(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(f.b.SetsHostDir(), "s1", "store", "wal_005", "000000010000000000000003.lz4")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(f.b, mf); err == nil {
		t.Fatal("a changed file passed")
	}
}

func TestANameIsChecked(t *testing.T) {
	f := newFixture(t)
	f.archive(t)
	for _, n := range []string{"../up", "UP", "a/b", ".tmp-x", "-x"} {
		if _, err := f.m.Create(context.Background(), n); codeOf(err) != codes.BackupSet {
			t.Errorf("%q: %v", n, err)
		}
	}
	if _, err := f.m.Create(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Create(context.Background(), "s1"); codeOf(err) != codes.BackupSet {
		t.Fatalf("a second s1: %v", err)
	}
	if err := f.m.Remove("nope"); codeOf(err) != codes.BackupSet {
		t.Fatalf("removing nothing: %v", err)
	}
	if err := f.m.Remove("s1"); err != nil {
		t.Fatal(err)
	}
}

func TestAGapTakesANewBaseBackup(t *testing.T) {
	f := newFixture(t)
	f.archive(t)
	if err := os.Remove(filepath.Join(f.b.StoreHostDir(), walDir, "000000010000000000000003.lz4")); err != nil {
		t.Fatal(err)
	}
	f.e.base = func() {
		f.e.lsn = "0/5000028"
		writeStore(t, f.b.StoreHostDir(), "basebackups_005/base_000000010000000000000005/x")
		body := []byte(`{"LSN":83886120,"PgVersion":180006,"SystemIdentifier":77,"UncompressedSize":1,"FinishTime":"2026-11-02T01:00:00Z"}`)
		if err := os.WriteFile(filepath.Join(f.b.StoreHostDir(), baseDir, "base_000000010000000000000005"+sentinelSuffix), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mf, err := f.m.Create(context.Background(), "after-gap")
	if err != nil {
		t.Fatal(err)
	}
	if f.e.bases != 1 || mf.Base != "base_000000010000000000000005" || len(f.e.points) != 2 || mf.Point != f.e.points[1] {
		t.Fatalf("bases %d, manifest %+v, points %v", f.e.bases, mf, f.e.points)
	}
}

func TestAFailedBaseBackupSaysSo(t *testing.T) {
	f := newFixture(t)
	f.e.base = func() { f.e.failing = strconv.Itoa(1) }
	if _, err := f.m.Create(context.Background(), "s1"); codeOf(err) != codes.BackupRoom {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.b.SetsHostDir(), "s1")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a failed set left a set")
	}
}

func TestAnExportOnlyARecoveryKeyOpens(t *testing.T) {
	f := newFixture(t)
	f.archive(t)
	if _, err := f.m.Create(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	f.m.Recipients = func() ([]string, error) { return []string{string(ssh.MarshalAuthorizedKey(sp))}, nil }
	var out bytes.Buffer
	if _, err := f.m.Export(context.Background(), "s1", &out); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte("before")) || bytes.Contains(out.Bytes(), []byte("wal wal_005")) {
		t.Fatal("the export carries clear text")
	}
	id, err := agessh.NewEd25519Identity(priv)
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(&out, id)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(r)
	names := map[string]bool{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names[h.Name] = true
	}
	if !names[ManifestFile] || !names["store/wal_005/000000010000000000000003.lz4"] {
		t.Fatalf("the export holds %v", names)
	}
	if f.logs[len(f.logs)-1] != "product.backup.export s1" {
		t.Fatalf("audit = %v", f.logs)
	}
}

func TestAnExportWithoutARecoveryKeyIsRefused(t *testing.T) {
	f := newFixture(t)
	f.archive(t)
	if _, err := f.m.Create(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
	f.m.Recipients = func() ([]string, error) { return nil, nil }
	var out bytes.Buffer
	if _, err := f.m.Export(context.Background(), "s1", &out); codeOf(err) != codes.Backup || out.Len() != 0 {
		t.Fatalf("got %v, %d bytes", err, out.Len())
	}
}

func codeOf(err error) int {
	c, _ := codes.Of(err)
	return c
}

// A cluster killed under a base backup records nothing, so the box asks again.
func TestABaseBackupLostToARestartIsAskedForAgain(t *testing.T) {
	f := newFixture(t)
	clock := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	f.m.Now = func() time.Time { clock = clock.Add(time.Minute); return clock }
	f.e.base = func() {
		if f.e.bases == 2 {
			f.archive(t)
		}
	}
	if _, err := f.m.Create(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
	if f.e.bases != 2 {
		t.Fatalf("asked %d times", f.e.bases)
	}
}
