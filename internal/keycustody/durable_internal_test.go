// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package keycustody

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A power cut right after first boot must not leave a sealed item empty:
// the new file's data is synced before the rename makes it the item, and
// the directory is synced after it, so the rename itself is on the disk.
// The cut is simulated by recording what reached the disk, in order, and
// checking the item only counts as written once both syncs are done.
func TestWriteDurableSyncsTheFileThenTheDirectory(t *testing.T) {
	dir := t.TempDir()
	var events []string
	old := syncFile
	syncFile = func(f *os.File) error {
		if fi, err := f.Stat(); err == nil && fi.IsDir() {
			if _, err := os.Stat(filepath.Join(dir, "ssh-user-ca")); err != nil {
				t.Error("the directory was synced before the rename")
			}
			events = append(events, "sync dir")
		} else {
			if _, err := os.Stat(filepath.Join(dir, "ssh-user-ca")); err == nil {
				t.Error("the item was renamed into place before its data was synced")
			}
			events = append(events, "sync file")
		}
		return f.Sync()
	}
	t.Cleanup(func() { syncFile = old })
	if err := writeDurable(dir, "ssh-user-ca", []byte("sealed")); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(events, []string{"sync file", "sync dir"}) {
		t.Fatalf("events %v", events)
	}
	got, err := os.ReadFile(filepath.Join(dir, "ssh-user-ca"))
	if err != nil || string(got) != "sealed" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".ssh-user-ca.new")); !os.IsNotExist(err) {
		t.Fatal("the temporary file stayed")
	}
}
