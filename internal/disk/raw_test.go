// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package disk_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	diskfs "github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/partition/gpt"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/kitout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

func writeFixtureDisk(t *testing.T) (string, *verify.State) {
	t.Helper()
	dir, pins := fixtures.Build(t, fixtures.Options{})
	s, err := verify.Run(context.Background(), verify.LocalLayout(dir), pins, verify.Options{KitVersion: fixtures.Version})
	if err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(t.TempDir(), "disk.raw")
	if err := disk.WriteInstalled(img, disk.MinDisk, s); err != nil {
		t.Fatal(err)
	}
	return img, s
}

func TestInstalledLayout(t *testing.T) {
	img, s := writeFixtureDisk(t)
	d, err := diskfs.Open(img, diskfs.WithOpenMode(diskfs.ReadOnly))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	pt, err := d.GetPartitionTable()
	if err != nil {
		t.Fatal(err)
	}
	parts := pt.(*gpt.Table).Partitions
	if len(parts) != 3 {
		t.Fatalf("%d partitions", len(parts))
	}
	want := disk.Installed()
	for i, p := range parts {
		if p.Name != want[i].Label || string(p.Type) != want[i].Type || int64(p.Start)*disk.SectorSize != want[i].Start || int64(p.Size) != want[i].Size {
			t.Errorf("partition %d: %+v, want %+v", i+1, p, want[i])
		}
	}
	slot, _ := disk.SlotGUID(s.Manifest.Spec.Root.Verity.RootHash)
	if !strings.EqualFold(parts[1].GUID, slot) {
		t.Fatalf("slot A PARTUUID %s, want %s", parts[1].GUID, slot)
	}
	f, _ := s.Layout.OpenBlob(s.Files[s.Manifest.Spec.Root.File])
	root, _ := io.ReadAll(f)
	_ = f.Close()
	raw, err := os.Open(img) // #nosec G304 -- the test's own image
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	got := make([]byte, len(root))
	if _, err := raw.ReadAt(got, disk.Installed()[1].Start); err != nil || !bytes.Equal(got, root) {
		t.Fatalf("slot A doesn't hold the root image (%v)", err)
	}
	fs, err := d.GetFilesystem(1)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{disk.ESPLoader, disk.ESPUKIDir + "/" + disk.UKIEntry(fixtures.Version), disk.ESPConf,
		disk.ESPKeysDir + "/PK.auth", disk.ESPKeysDir + "/KEK.auth", disk.ESPKeysDir + "/db.auth"} {
		fh, err := fs.OpenFile(name, os.O_RDONLY)
		if err != nil {
			t.Errorf("ESP %s: %v", name, err)
			continue
		}
		_ = fh.Close()
	}
}

func TestInstalledDiskIsSparse(t *testing.T) {
	img, _ := writeFixtureDisk(t)
	st, err := os.Stat(img)
	if err != nil || st.Size() != disk.MinDisk {
		t.Fatalf("size %d %v", st.Size(), err)
	}
}

func TestSgdiskReadsTheTable(t *testing.T) {
	bin, err := exec.LookPath("sgdisk")
	if err != nil {
		if os.Getenv("SNEAKERS_REQUIRE_TOOLS") != "" {
			t.Fatal("sgdisk isn't installed and SNEAKERS_REQUIRE_TOOLS is set")
		}
		t.Skip("sgdisk isn't installed; CI installs it")
	}
	img, s := writeFixtureDisk(t)
	out, err := exec.Command(bin, "-v", img).CombinedOutput() // #nosec G204 -- test-only, fixed tool
	if err != nil || !strings.Contains(string(out), "No problems found") {
		t.Fatalf("sgdisk -v: %v\n%s", err, out)
	}
	out, err = exec.Command(bin, "-i", "2", img).CombinedOutput() // #nosec G204 -- as above
	slot, _ := disk.SlotGUID(s.Manifest.Spec.Root.Verity.RootHash)
	if err != nil || !strings.Contains(strings.ToLower(string(out)), slot) || !strings.Contains(string(out), disk.LabelRootA) {
		t.Fatalf("sgdisk -i 2: %v\n%s", err, out)
	}
}

func TestRawWriterThroughTheKit(t *testing.T) {
	dir, pins := fixtures.Build(t, fixtures.Options{})
	out := t.TempDir()
	paths, err := kitout.NewWriters(disk.Raw{}).Run(context.Background(), verify.LocalLayout(dir), pins, "raw", kitout.Options{Out: out, KitVersion: fixtures.Version})
	if err != nil || len(paths) != 1 || filepath.Base(paths[0]) != "sneakers-appliance-lab-"+fixtures.Version+"-amd64.raw" {
		t.Fatalf("%v %v", paths, err)
	}
}

func TestWriteInstalledRefusesASmallDisk(t *testing.T) {
	dir, pins := fixtures.Build(t, fixtures.Options{})
	s, err := verify.Run(context.Background(), verify.LocalLayout(dir), pins, verify.Options{KitVersion: fixtures.Version})
	if err != nil {
		t.Fatal(err)
	}
	if err := disk.WriteInstalled(filepath.Join(t.TempDir(), "x"), 32*disk.GiB, s); err == nil {
		t.Fatal("32 GiB is under the minimum")
	}
}
