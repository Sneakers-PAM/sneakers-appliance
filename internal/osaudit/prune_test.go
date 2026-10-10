// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osaudit_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

// fiveDays writes one entry a day for five days and returns the clock.
func fiveDays(t *testing.T, o osaudit.Options) (*osaudit.Log, *fakeClock, string) {
	t.Helper()
	dir := t.TempDir()
	clk := &fakeClock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	o.Now = clk.Now
	l, err := osaudit.Open(dir, o)
	mustNoErr(t, err)
	for i := range 5 {
		mustNoErr(t, l.Append(padded(i)))
		clk.Advance(24 * time.Hour)
	}
	mustNoErr(t, l.Append(padded(5)))
	return l, clk, dir
}

func lastLineHash(t *testing.T, b []byte) string {
	t.Helper()
	lines := bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
	s := sha256.Sum256(lines[len(lines)-1])
	return hex.EncodeToString(s[:])
}

// A file past retention moves to the archive on the backup volume, byte
// for byte, before it leaves the log directory, and each removal is an
// os-audit.prune entry naming the file, its hash, its chain link and why.
func TestPruneArchivesFirstAndAudits(t *testing.T) {
	archive := t.TempDir()
	l, _, dir := fiveDays(t, osaudit.Options{ArchiveDir: archive})
	_, err := l.Compress()
	mustNoErr(t, err)
	want := map[string][]byte{}
	for _, f := range logFiles(t, dir) {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		want[f] = b
	}
	l.SetRetention(2*24*time.Hour, 90*24*time.Hour)
	mustNoErr(t, l.Prune())

	left := logFiles(t, dir)
	pruned := []string{}
	for f := range want {
		if !slices.Contains(left, f) {
			pruned = append(pruned, f)
		}
	}
	slices.Sort(pruned)
	if len(pruned) != 3 {
		t.Fatalf("pruned %v, left %v", pruned, left)
	}
	es, err := l.Entries()
	mustNoErr(t, err)
	var prunes []osaudit.Entry
	for _, e := range es {
		if e.Action == osaudit.ActionPrune {
			prunes = append(prunes, e)
		}
	}
	if len(prunes) != len(pruned) {
		t.Fatalf("%d prune entries for %d files", len(prunes), len(pruned))
	}
	for i, f := range pruned {
		got, err := os.ReadFile(filepath.Join(archive, f))
		if err != nil || !bytes.Equal(got, want[f]) {
			t.Fatalf("%s isn't in the archive as it was: %v", f, err)
		}
		e := prunes[i]
		plain := fileSHABytes(t, filepath.Join(archive, f))
		if e.Detail["file"] != strings.TrimSuffix(f, ".gz") || e.Detail["sha256"] != fileSHA(t, filepath.Join(archive, f)) ||
			e.Detail["lastLineSha256"] != lastLineHash(t, plain) || e.Detail["archived"] != filepath.Join(archive, f) ||
			!strings.Contains(e.Detail["reason"], "retention") || e.Actor != "os-audit" {
			t.Fatalf("prune entry %d: %+v", i, e)
		}
	}
	mustNoErr(t, l.Verify())
	if b := l.PruneBlocked(); len(b) != 0 {
		t.Fatalf("blocked %v", b)
	}
}

func fileSHABytes(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	mustNoErr(t, err)
	if strings.HasSuffix(p, ".gz") {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		mustNoErr(t, err)
		out, err := io.ReadAll(zr)
		mustNoErr(t, err)
		return out
	}
	return b
}

// A file the archive already holds, the same bytes, isn't copied again;
// the removal is still audited.
func TestPruneUsesAnArchivedCopy(t *testing.T) {
	archive := t.TempDir()
	l, _, dir := fiveDays(t, osaudit.Options{ArchiveDir: archive})
	first := logFiles(t, dir)[0]
	b, _ := os.ReadFile(filepath.Join(dir, first))
	mustNoErr(t, os.WriteFile(filepath.Join(archive, first), b, 0o600))
	l.SetRetention(4*24*time.Hour, 90*24*time.Hour)
	mustNoErr(t, l.Prune())
	if slices.Contains(logFiles(t, dir), first) {
		t.Fatal("the archived file is still in the log directory")
	}
	es, _ := l.Entries()
	if last := es[len(es)-1]; last.Action != osaudit.ActionPrune || last.Detail["copied"] != "no" {
		t.Fatalf("%+v", last)
	}
}

// Nothing is removed when the archive can't take the file: no archive
// directory, one that isn't a directory (the backup volume full or
// missing), or a different file of the same name there. The file stays
// and PruneBlocked says which and why, for Status.
func TestPruneKeepsWhatCantBeArchived(t *testing.T) {
	notDir := filepath.Join(t.TempDir(), "file")
	mustNoErr(t, os.WriteFile(notDir, nil, 0o600))
	clash := t.TempDir()
	for name, archive := range map[string]string{"no archive": "", "not a directory": notDir, "a clash": clash} {
		t.Run(name, func(t *testing.T) {
			l, _, dir := fiveDays(t, osaudit.Options{ArchiveDir: archive})
			before := logFiles(t, dir)
			if archive == clash {
				mustNoErr(t, os.WriteFile(filepath.Join(clash, before[0]), []byte("other\n"), 0o600))
			}
			l.SetRetention(4*24*time.Hour, 90*24*time.Hour)
			mustNoErr(t, l.Prune())
			if after := logFiles(t, dir); !slices.Equal(after, before) {
				t.Fatalf("files %v, before %v", after, before)
			}
			b := l.PruneBlocked()
			if len(b) != 1 || b[0].File != before[0] || b[0].Reason == "" {
				t.Fatalf("blocked %+v", b)
			}
			es, _ := l.Entries()
			for _, e := range es {
				if e.Action == osaudit.ActionPrune {
					t.Fatalf("a prune entry for a kept file: %+v", e)
				}
			}
		})
	}
}
