// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package imageupgrade_test

import (
	"os"
	"path"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/imageupgrade"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

func parsed(t *testing.T, names ...string) []imageupgrade.Entry {
	t.Helper()
	var out []imageupgrade.Entry
	for _, n := range names {
		e, ok := imageupgrade.ParseEntry(n)
		if !ok {
			t.Fatalf("%s doesn't parse", n)
		}
		out = append(out, e)
	}
	return out
}

func versions(es []imageupgrade.Entry) []string {
	out := []string{}
	for _, e := range es {
		out = append(out, e.Version)
	}
	return out
}

func TestRetainKeepsNAndDropsTheOldest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []string
		running string
		keep    int
		drop    []string
	}{
		{"nothing but the running release", []string{"sneakers-0.2.0.efi"}, "0.2.0", 2, []string{}},
		{"two kept: staging drops the previous", []string{"sneakers-0.1.0.efi", "sneakers-0.2.0.efi"}, "0.2.0", 2, []string{"0.1.0"}},
		{"two kept: staging again drops the staged one", []string{"sneakers-0.2.0.efi", "sneakers-0.3.0+3-0.efi"}, "0.2.0", 2, []string{"0.3.0"}},
		{"three kept: the oldest goes, the newest other stays", []string{"sneakers-0.1.0.efi", "sneakers-0.2.0.efi", "sneakers-0.3.0.efi"}, "0.3.0", 3, []string{"0.1.0"}},
		{"three kept: a bad entry goes before a good older one", []string{"sneakers-0.1.0.efi", "sneakers-0.2.0.efi", "sneakers-0.3.0+0-3.efi"}, "0.2.0", 3, []string{"0.3.0"}},
		{"the running release is kept whatever its age", []string{"sneakers-0.1.0.efi", "sneakers-0.2.0.efi", "sneakers-0.3.0.efi"}, "0.1.0", 3, []string{"0.2.0"}},
		{"keep under two still keeps the running release", []string{"sneakers-0.1.0.efi", "sneakers-0.2.0.efi"}, "0.2.0", 1, []string{"0.1.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := versions(imageupgrade.Retain(parsed(t, tc.entries...), tc.running, tc.keep))
			if !reflect.DeepEqual(got, tc.drop) {
				t.Fatalf("dropped %v; want %v", got, tc.drop)
			}
		})
	}
}

func TestKeepIsCappedByTheRootPartitions(t *testing.T) {
	for in, want := range map[int]int{0: imageupgrade.DefaultKeep, 1: 2, 2: 2, 3: imageupgrade.MaxKeep} {
		if got := (&imageupgrade.Stager{Keep: in}).Keeps(); got != want {
			t.Errorf("Keep %d: keeps %d; want %d", in, got, want)
		}
	}
	if imageupgrade.MaxKeep != 2 || imageupgrade.DefaultKeep != 2 {
		t.Fatal("the boot disk has two root partitions: at most and by default two releases")
	}
}

// Three updates in a row: each stage leaves the running release and the
// staged one, names what it removed, and leaves no fetched copy, .tmp
// file or older entry behind.
func TestThreeStagesInARowStayFlat(t *testing.T) {
	s, _, _, _, _ := stager(t, "0.0.7")
	esp := s.ESP.(orderESP).dir
	ukis := filepath.Join(esp, imageupgrade.UKIDir)
	for _, junk := range []string{filepath.Join(ukis, "sneakers-0.0.5.efi.tmp"), filepath.Join(esp, imageupgrade.RevertedFile+".tmp"), filepath.Join(s.WorkDir, "sha256-stale", "blob")} {
		if err := os.MkdirAll(filepath.Dir(junk), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(junk, []byte("left over"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ukis, imageupgrade.GoodName("0.0.6")), []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	var sizes []int64
	staged := path.Join(imageupgrade.UKIDir, imageupgrade.EntryName(fixtures.Version, imageupgrade.Tries, 0))
	for i, running := range []string{"0.0.7", "0.0.8", "0.0.9"} {
		if i > 0 {
			// Boot into the release staged last, as the next version up
			// (the fixture release is always the same one): it's marked
			// good.
			if err := s.ESP.Rename(staged, path.Join(imageupgrade.UKIDir, imageupgrade.EntryName(running, imageupgrade.Tries-1, 1))); err != nil {
				t.Fatal(err)
			}
			s.Running = running
			if err := s.MarkGood(ctx, nil); err != nil {
				t.Fatal(err)
			}
		}
		next, err := s.NextStageRemoves()
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{[]string{"0.0.6", "0.0.7", "0.0.8"}[i]}; !reflect.DeepEqual(next, want) {
			t.Fatalf("update %d: the next stage removes %v; want %v", i+1, next, want)
		}
		dir, _ := fixtures.Build(t, fixtures.Options{})
		if _, err := s.Stage(ctx, verify.LocalLayout(dir), "amd64"); err != nil {
			t.Fatal(err)
		}
		got, _ := s.ESP.List(imageupgrade.UKIDir)
		if want := []string{imageupgrade.GoodName(running), path.Base(staged)}; !reflect.DeepEqual(got, want) {
			t.Fatalf("update %d: the ESP holds %v; want %v", i+1, got, want)
		}
		if left, _ := os.ReadDir(s.WorkDir); len(left) != 0 {
			t.Fatalf("update %d: the work directory still holds %d entries", i+1, len(left))
		}
		if _, err := os.Stat(filepath.Join(esp, imageupgrade.RevertedFile+".tmp")); !os.IsNotExist(err) {
			t.Fatalf("update %d: a .tmp file is left on the ESP", i+1)
		}
		sizes = append(sizes, treeSize(t, esp))
	}
	// The first running entry is a stand-in; from the second update on
	// both entries are real UKIs.
	if sizes[2] != sizes[1] {
		t.Fatalf("the ESP grew across updates: %v", sizes)
	}
}

func treeSize(t *testing.T, dir string) int64 {
	t.Helper()
	var n int64
	err := filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			n += fi.Size()
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}
