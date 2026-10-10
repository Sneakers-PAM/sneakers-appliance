// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osaudit_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/osaudit"
)

func logFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	mustNoErr(t, err)
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "log-") {
			out = append(out, e.Name())
		}
	}
	return out
}

func fileSHA(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	mustNoErr(t, err)
	if strings.HasSuffix(p, ".gz") {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		mustNoErr(t, err)
		b, err = io.ReadAll(zr)
		mustNoErr(t, err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func padded(i int) osaudit.Entry {
	return osaudit.Entry{Actor: "alice", Action: fmt.Sprintf("a%d", i), Target: strings.Repeat("x", 120)}
}

// A day file that reaches the size cap rolls over to a numbered part; the
// part's first line links to the file before it, and the chain verifies
// across every file.
func TestSizeRotationKeepsChain(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{t: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	l, err := osaudit.Open(dir, osaudit.Options{Now: clk.Now, MaxFileSize: 1024})
	mustNoErr(t, err)
	for i := range 40 {
		mustNoErr(t, l.Append(padded(i)))
	}
	files := logFiles(t, dir)
	if len(files) < 3 {
		t.Fatalf("files %v: want the day to roll over by size", files)
	}
	if files[0] != "log-2026-10-09.jsonl" || files[1] != "log-2026-10-09.p0001.jsonl" {
		t.Fatalf("files %v", files)
	}
	for _, f := range files[:len(files)-1] {
		if fi, _ := os.Stat(filepath.Join(dir, f)); fi.Size() > 1024+400 {
			t.Fatalf("%s is %d bytes, over the cap by more than a line", f, fi.Size())
		}
	}
	mustNoErr(t, l.Verify())
	es, err := l.Entries()
	mustNoErr(t, err)
	var links []osaudit.Entry
	n := 0
	for _, e := range es {
		if e.Action == osaudit.ActionRotate {
			links = append(links, e)
			continue
		}
		if e.Action != fmt.Sprintf("a%d", n) {
			t.Fatalf("entry %d is %s", n, e.Action)
		}
		n++
	}
	if n != 40 || len(links) != len(files)-1 {
		t.Fatalf("%d entries, %d links for %d files", n, len(links), len(files))
	}
	for i, link := range links {
		if link.Detail["previous"] != files[i] || link.Detail["previousSha256"] != fileSHA(t, filepath.Join(dir, files[i])) || link.Detail["previousLines"] == "" {
			t.Fatalf("link %d: %+v", i, link.Detail)
		}
	}
}

// A second writer (init and accessd both append) rolls over the same way
// and keeps the one chain.
func TestRotationWithTwoWriters(t *testing.T) {
	dir := t.TempDir()
	a, err := osaudit.Open(dir, osaudit.Options{MaxFileSize: 800})
	mustNoErr(t, err)
	b, err := osaudit.Open(dir, osaudit.Options{MaxFileSize: 800})
	mustNoErr(t, err)
	for i := range 30 {
		w := a
		if i%3 == 0 {
			w = b
		}
		mustNoErr(t, w.Append(padded(i)))
	}
	mustNoErr(t, a.Verify())
	mustNoErr(t, b.Verify())
}

// A link whose recorded hash doesn't match the file before it fails
// verification even when every line still chains: the earlier file was
// swapped for another with the same last line.
func TestRotationLinkChecked(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{t: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	l, err := osaudit.Open(dir, osaudit.Options{Now: clk.Now, MaxFileSize: 1024})
	mustNoErr(t, err)
	for i := range 20 {
		mustNoErr(t, l.Append(padded(i)))
	}
	first := filepath.Join(dir, "log-2026-10-09.jsonl")
	b, err := os.ReadFile(first)
	mustNoErr(t, err)
	lines := bytes.SplitAfter(b, []byte("\n"))
	// Keep only the last line: it still anchors (the oldest line left) and
	// the next file still chains to it.
	mustNoErr(t, os.WriteFile(first, lines[len(lines)-2], 0o600))
	if err := l.Verify(); err == nil {
		t.Fatal("a file cut down to its last line verified against its link")
	}
}

// Compress turns every closed file into .jsonl.gz and leaves the newest;
// the chain, the entries and the next append carry on.
func TestCompressKeepsChain(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	l, err := osaudit.Open(dir, osaudit.Options{Now: clk.Now})
	mustNoErr(t, err)
	for i := range 30 {
		mustNoErr(t, l.Append(padded(i)))
		if i%10 == 9 {
			clk.Advance(24 * time.Hour)
		}
	}
	before, err := l.Entries()
	mustNoErr(t, err)
	res, err := l.Compress()
	mustNoErr(t, err)
	if res.Files != 2 || res.Freed <= 0 {
		t.Fatalf("compress %+v", res)
	}
	files := logFiles(t, dir)
	want := []string{"log-2026-10-01.jsonl.gz", "log-2026-10-02.jsonl.gz", "log-2026-10-03.jsonl"}
	if !slices.Equal(files, want) {
		t.Fatalf("files %v, want %v", files, want)
	}
	mustNoErr(t, l.Verify())
	after, err := l.Entries()
	mustNoErr(t, err)
	if len(after) != len(before) {
		t.Fatalf("%d entries after, %d before", len(after), len(before))
	}
	l2, err := osaudit.Open(dir, osaudit.Options{Now: clk.Now})
	mustNoErr(t, err)
	mustNoErr(t, l2.Append(osaudit.Entry{Actor: "console", Action: "after"}))
	mustNoErr(t, l2.Verify())
	// The append went to a new day, so the third day's file is closed now.
	if res, err := l2.Compress(); err != nil || res.Files != 1 {
		t.Fatalf("a second compress: %+v %v", res, err)
	}
	if res, err := l2.Compress(); err != nil || res.Files != 0 {
		t.Fatalf("a third compress: %+v %v", res, err)
	}
	mustNoErr(t, l2.Verify())
}

// A compress cut off after the .gz was written but before the plain file
// went leaves both; the plain one counts once and the next run tidies.
func TestCompressLeftoverReadsOnce(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	l, err := osaudit.Open(dir, osaudit.Options{Now: clk.Now})
	mustNoErr(t, err)
	mustNoErr(t, l.Append(padded(0)))
	clk.Advance(24 * time.Hour)
	mustNoErr(t, l.Append(padded(1)))
	old := filepath.Join(dir, "log-2026-10-01.jsonl")
	b, err := os.ReadFile(old)
	mustNoErr(t, err)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(b)
	mustNoErr(t, zw.Close())
	mustNoErr(t, os.WriteFile(old+".gz", gz.Bytes(), 0o600))
	es, err := l.Entries()
	mustNoErr(t, err)
	if len(es) != 2 {
		t.Fatalf("%d entries with a leftover .gz", len(es))
	}
	_, err = l.Compress()
	mustNoErr(t, err)
	if files := logFiles(t, dir); !slices.Equal(files, []string{"log-2026-10-01.jsonl.gz", "log-2026-10-02.jsonl"}) {
		t.Fatalf("files %v", files)
	}
	mustNoErr(t, l.Verify())
}

// The archive over its cap is flagged first and stays; once the warning
// has stood for the grace period the oldest files move to the export
// directory, byte for byte, and the move is audited.
func TestArchiveFlagsBeforeExport(t *testing.T) {
	dir, exp := t.TempDir(), t.TempDir()
	clk := &fakeClock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	l, err := osaudit.Open(dir, osaudit.Options{Now: clk.Now})
	mustNoErr(t, err)
	for i := range 10 {
		mustNoErr(t, l.Append(padded(i)))
		clk.Advance(24 * time.Hour)
	}
	mustNoErr(t, l.Append(padded(10)))
	_, err = l.Compress()
	mustNoErr(t, err)
	shas := map[string]string{}
	var archived int64
	for _, f := range logFiles(t, dir) {
		shas[f] = fileSHA(t, filepath.Join(dir, f))
		if strings.HasSuffix(f, ".gz") {
			fi, _ := os.Stat(filepath.Join(dir, f))
			archived += fi.Size()
		}
	}
	opt := osaudit.ArchiveOptions{MaxBytes: archived / 2, MaxFiles: 100, Grace: 24 * time.Hour, ExportDir: exp}

	r, err := l.Archive(opt)
	mustNoErr(t, err)
	if len(r.Flagged) == 0 || len(r.Exported) != 0 {
		t.Fatalf("first look: %+v", r)
	}
	if r.ExportAfter.Sub(clk.t) != 24*time.Hour {
		t.Fatalf("export after %v", r.ExportAfter)
	}
	if fs := logFiles(t, exp); len(fs) != 0 {
		t.Fatalf("exported before the grace: %v", fs)
	}
	clk.Advance(2 * time.Hour)
	if r, err := l.Archive(opt); err != nil || len(r.Exported) != 0 || len(r.Flagged) == 0 {
		t.Fatalf("inside the grace: %+v %v", r, err)
	}

	clk.Advance(23 * time.Hour)
	r, err = l.Archive(opt)
	mustNoErr(t, err)
	if len(r.Exported) == 0 || len(r.Flagged) != 0 {
		t.Fatalf("after the grace: %+v", r)
	}
	for _, f := range r.Exported {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Fatalf("%s is still in the log directory", f)
		}
		if got := fileSHA(t, filepath.Join(exp, f)); got != shas[f] {
			t.Fatalf("%s changed on export", f)
		}
	}
	mustNoErr(t, l.Verify())
	es, err := l.Entries()
	mustNoErr(t, err)
	last := es[len(es)-1]
	if last.Action != osaudit.ActionArchiveExport || last.Detail["files"] != fmt.Sprint(len(r.Exported)) || last.Detail["to"] != exp {
		t.Fatalf("the export isn't audited: %+v", last)
	}
}

// An export directory that can't take the files leaves them where they
// are, flagged, and says why.
func TestArchiveExportFailsKeepsFiles(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{t: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	l, err := osaudit.Open(dir, osaudit.Options{Now: clk.Now})
	mustNoErr(t, err)
	for i := range 4 {
		mustNoErr(t, l.Append(padded(i)))
		clk.Advance(24 * time.Hour)
	}
	_, err = l.Compress()
	mustNoErr(t, err)
	before := logFiles(t, dir)
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	mustNoErr(t, os.WriteFile(blocker, nil, 0o600))
	opt := osaudit.ArchiveOptions{MaxBytes: 1, MaxFiles: 100, Grace: time.Hour, ExportDir: blocker}
	_, err = l.Archive(opt)
	mustNoErr(t, err)
	clk.Advance(2 * time.Hour)
	r, err := l.Archive(opt)
	if err == nil || len(r.Exported) != 0 || len(r.Flagged) == 0 {
		t.Fatalf("%+v %v", r, err)
	}
	if after := logFiles(t, dir); !slices.Equal(after, before) {
		t.Fatalf("files %v, before %v", after, before)
	}
}

// ReadFiles hands every file, oldest first and decompressed, so the
// :8443 export streams the log as written.
func TestReadFilesDecompresses(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	l, err := osaudit.Open(dir, osaudit.Options{Now: clk.Now})
	mustNoErr(t, err)
	var want bytes.Buffer
	for i := range 3 {
		mustNoErr(t, l.Append(padded(i)))
		clk.Advance(24 * time.Hour)
	}
	for _, f := range logFiles(t, dir) {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		want.Write(b)
	}
	_, err = l.Compress()
	mustNoErr(t, err)
	var got bytes.Buffer
	mustNoErr(t, l.ReadFiles(func(name string, r io.Reader) error {
		_, err := io.Copy(&got, r)
		return err
	}))
	if !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatal("the files read back differ from what was written")
	}
}
