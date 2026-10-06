// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package disk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	diskfs "github.com/diskfs/go-diskfs"
	godisk "github.com/diskfs/go-diskfs/disk"
	"github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/partition/gpt"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/kitout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
	"github.com/Sneakers-PAM/sneakers-appliance/os/loader"
)

// Paths on the ESP.
const (
	ESPLoader  = "EFI/BOOT/BOOTX64.EFI"
	ESPUKIDir  = "EFI/Linux"
	ESPConf    = "loader/loader.conf"
	ESPKeysDir = "loader/keys/sneakers"
)

// UKIEntry is the ESP file name of the installed release's UKI. The first
// install is known good, so it carries no boot counter.
func UKIEntry(version string) string { return "sneakers-" + version + ".efi" }

// WriteInstalled writes the installed amd64 disk image to a new sparse file
// at p: a GPT with the ESP (systemd-boot, the UKI, loader.conf and the
// signed enrolment files), root slot A holding the root image with its
// PARTUUID taken from the root hash, and an empty slot B. First boot adds
// the rest. Nothing needs root or a loop device.
func WriteInstalled(p string, size int64, s *verify.State) error {
	if size < MinDisk {
		return fmt.Errorf("disk: %d bytes is under the 64 GiB minimum", size)
	}
	if size%SectorSize != 0 {
		return fmt.Errorf("disk: size %d isn't a whole number of sectors", size)
	}
	m := s.Manifest
	slotA, err := SlotGUID(m.Spec.Root.Verity.RootHash)
	if err != nil {
		return err
	}
	rootSize := s.Files[m.Spec.Root.File].Size
	if rootSize > SlotSize("amd64") {
		return fmt.Errorf("disk: the root image is %d bytes, more than a %d-byte slot", rootSize, SlotSize("amd64"))
	}
	d, err := diskfs.Create(p, size, diskfs.SectorSize512)
	if err != nil {
		return fmt.Errorf("disk: create %s: %w", p, err)
	}
	defer func() { _ = d.Close() }()
	var parts []*gpt.Partition
	for _, q := range Installed() {
		gp := &gpt.Partition{
			Index: q.Number, Start: uint64(q.Start / SectorSize), End: uint64((q.Start+q.Size)/SectorSize - 1), // #nosec G115 -- positive, from the fixed layout
			Size: uint64(q.Size), Type: gpt.Type(q.Type), Name: q.Label, // #nosec G115 -- as above
		}
		if q.Label == LabelRootA {
			gp.GUID = slotA
		}
		parts = append(parts, gp)
	}
	if err := d.Partition(&gpt.Table{Partitions: parts, LogicalSectorSize: SectorSize, PhysicalSectorSize: SectorSize, ProtectiveMBR: true}); err != nil {
		return fmt.Errorf("disk: write the partition table: %w", err)
	}
	if err := writeAt(p, Installed()[1].Start, s, m.Spec.Root.File); err != nil {
		return fmt.Errorf("disk: write root slot A: %w", err)
	}
	fs, err := d.CreateFilesystem(godisk.FilesystemSpec{Partition: 1, FSType: filesystem.TypeFat32, VolumeLabel: "ESP"})
	if err != nil {
		return fmt.Errorf("disk: format the ESP: %w", err)
	}
	put := func(name string, r io.Reader) error {
		if err := fs.Mkdir(path.Dir(name)); err != nil {
			return err
		}
		f, err := fs.OpenFile(name, os.O_CREATE|os.O_RDWR)
		if err != nil {
			return fmt.Errorf("disk: ESP %s: %w", name, err)
		}
		if _, err := io.Copy(f, r); err != nil {
			_ = f.Close()
			return fmt.Errorf("disk: ESP %s: %w", name, err)
		}
		return f.Close()
	}
	blob := func(title string) (io.ReadCloser, error) { return s.Layout.OpenBlob(s.Files[title]) }
	for _, e := range []struct{ dst, title string }{
		{ESPLoader, m.Spec.Boot.Loader.File},
		{ESPUKIDir + "/" + UKIEntry(m.Metadata.Version), m.Spec.Boot.UKI.File},
		{ESPKeysDir + "/PK.auth", verify.SecureBootKeyPrefix + "PK.auth"},
		{ESPKeysDir + "/KEK.auth", verify.SecureBootKeyPrefix + "KEK.auth"},
		{ESPKeysDir + "/db.auth", verify.SecureBootKeyPrefix + "db.auth"},
	} {
		r, err := blob(e.title)
		if err != nil {
			return err
		}
		err = put(e.dst, r)
		_ = r.Close()
		if err != nil {
			return err
		}
	}
	return put(ESPConf, bytes.NewReader(loader.Conf))
}

// writeAt copies a blob into the image at off, leaving the rest sparse.
func writeAt(img string, off int64, s *verify.State, title string) error {
	in, err := s.Layout.OpenBlob(s.Files[title])
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(img, os.O_WRONLY, 0) // #nosec G304 -- the image this writer just created
	if err != nil {
		return err
	}
	if _, err := io.Copy(io.NewOffsetWriter(out, off), in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// Raw is the raw kitout format: the installed disk image itself.
type Raw struct{}

// Format names the format.
func (Raw) Format() string { return "raw" }

// Arches lists the supported architectures; arm64 arrives with the Pi
// layout.
func (Raw) Arches() []string { return []string{"amd64"} }

// Write writes <base>.raw into dir.
func (Raw) Write(_ context.Context, s *verify.State, o kitout.Options, dir string) error {
	size := o.DiskSize
	if size == 0 {
		size = MinDisk
	}
	return WriteInstalled(filepath.Join(dir, kitout.BaseName(s)+".raw"), size, s)
}
