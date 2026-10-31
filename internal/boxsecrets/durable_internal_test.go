// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package boxsecrets

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A power cut must leave box-secrets.json whole, old or new: the new file's
// data is synced before the rename makes it the file, and the directory is
// synced after it, so the rename itself is on the disk. The cut is simulated
// by recording what reached the disk, in order.
func TestWriteAtomicSyncsTheFileThenTheDirectory(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ValuesFile)
	if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	var events []string
	old := syncFile
	syncFile = func(f *os.File) error {
		on, err := os.ReadFile(p) // #nosec G304 -- the test's own file
		if err != nil {
			t.Fatal(err)
		}
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if fi.IsDir() {
			if string(on) != "new" {
				t.Error("the directory was synced before the rename")
			}
			events = append(events, "sync dir")
		} else {
			if string(on) != "old" {
				t.Error("the file was renamed into place before its data was synced")
			}
			events = append(events, "sync file")
		}
		return f.Sync()
	}
	t.Cleanup(func() { syncFile = old })
	if err := writeAtomic(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(events, []string{"sync file", "sync dir"}) {
		t.Fatalf("events %v", events)
	}
	if _, err := os.Stat(p + ".new"); !os.IsNotExist(err) {
		t.Fatal("the temporary file stayed")
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
}

// When the data can't be synced the old file stays, and the rename never
// happens: renaming unsynced data over it is the failure this guards against.
func TestWriteAtomicKeepsTheOldFileWhenTheSyncFails(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ValuesFile)
	if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := syncFile
	syncFile = func(*os.File) error { return errors.New("disk gone") }
	t.Cleanup(func() { syncFile = old })
	if err := writeAtomic(p, []byte("new")); err == nil {
		t.Fatal("no error")
	}
	got, err := os.ReadFile(p) // #nosec G304 -- the test's own file
	if err != nil || string(got) != "old" {
		t.Fatalf("%q %v", got, err)
	}
}
