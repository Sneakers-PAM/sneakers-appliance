// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package ova writes the OVA for VMware (spec 1 Section 2.4): the installed
// disk as a stream-optimized VMDK, an OVF descriptor from the template, and
// a manifest of their SHA-256s, in one tar in OVA order.
package ova

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/kitout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
)

//go:embed template.ovf
var ovfTemplate string

var tmpl = template.Must(template.New("ovf").Parse(ovfTemplate))

// Params fill the OVF template.
type Params struct {
	Name, Version string
	VMDK          string
	VMDKSize      int64
	DiskBytes     int64
	CPUs          int
	MemoryMiB     int
	// AuthBypass sets uefi.allowAuthBypass for the first boot. Spike S1
	// ran the delete-the-PK step with it on; until the test phase shows the
	// step works without it, the OVF carries it and the console tells the
	// admin to remove it after enrolment.
	AuthBypass bool
}

// Render fills the template, with the spec's defaults for what's unset.
func Render(p Params) string {
	if p.CPUs == 0 {
		p.CPUs = 4
	}
	if p.MemoryMiB == 0 {
		p.MemoryMiB = 16384
	}
	if p.Name == "" {
		p.Name = "sneakers-" + p.Version
	}
	if p.VMDK == "" {
		p.VMDK = p.Name + "-disk1.vmdk"
	}
	var b bytes.Buffer
	if err := tmpl.Execute(&b, p); err != nil {
		panic(err) // the template is embedded and its fields fixed
	}
	return b.String()
}

// OVA is the ova kitout format.
type OVA struct{}

// Format names the format.
func (OVA) Format() string { return "ova" }

// Arches lists the supported architectures.
func (OVA) Arches() []string { return []string{"amd64"} }

// Write writes <base>.ova into dir. It needs qemu-img (KIT_TOOL_MISSING
// otherwise), which the kit's container carries.
func (OVA) Write(ctx context.Context, s *verify.State, o kitout.Options, dir string) error {
	qemuImg, err := exec.LookPath("qemu-img")
	if err != nil {
		return codes.New(codes.KitToolMissing, "the ova format needs qemu-img; use the kit's container or install it")
	}
	size := o.DiskSize
	if size == 0 {
		size = disk.MinDisk
	}
	work, err := os.MkdirTemp(dir, ".ova-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()
	raw := filepath.Join(work, "disk.raw")
	if err := disk.WriteInstalled(raw, size, s); err != nil {
		return err
	}
	base := kitout.BaseName(s)
	vmdkName := base + "-disk1.vmdk"
	vmdk := filepath.Join(work, vmdkName)
	cmd := exec.CommandContext(ctx, qemuImg, "convert", "-f", "raw", "-O", "vmdk", "-o", "subformat=streamOptimized", raw, vmdk) // #nosec G204 -- qemu-img with fixed verbs
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ova: qemu-img convert: %w: %s", err, out)
	}
	st, err := os.Stat(vmdk)
	if err != nil {
		return err
	}
	ovfName := base + ".ovf"
	ovf := Render(Params{Name: base, Version: s.Manifest.Metadata.Version, VMDK: vmdkName, VMDKSize: st.Size(), DiskBytes: size, AuthBypass: true})
	vmdkSum, err := fileSHA(vmdk)
	if err != nil {
		return err
	}
	ovfSum := sha256.Sum256([]byte(ovf))
	mf := fmt.Sprintf("SHA256(%s)= %s\nSHA256(%s)= %s\n", ovfName, hex.EncodeToString(ovfSum[:]), vmdkName, vmdkSum)
	return writeTar(filepath.Join(dir, base+".ova"), []member{
		{name: ovfName, data: []byte(ovf)},
		{name: base + ".mf", data: []byte(mf)},
		{name: vmdkName, path: vmdk},
	})
}

type member struct {
	name string
	data []byte
	path string
}

// writeTar writes members in order, which OVA requires: descriptor first,
// then the manifest, then the disks.
func writeTar(p string, members []member) error {
	f, err := os.Create(p) // #nosec G304 -- the writer's own output in its work directory
	if err != nil {
		return err
	}
	tw := tar.NewWriter(f)
	for _, m := range members {
		var r io.Reader = bytes.NewReader(m.data)
		size := int64(len(m.data))
		if m.path != "" {
			in, err := os.Open(m.path) // #nosec G304 -- as above
			if err != nil {
				_ = f.Close()
				return err
			}
			defer func() { _ = in.Close() }()
			st, err := in.Stat()
			if err != nil {
				_ = f.Close()
				return err
			}
			r, size = in, st.Size()
		}
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o644, Size: size, Format: tar.FormatUSTAR}); err != nil {
			_ = f.Close()
			return err
		}
		if _, err := io.Copy(tw, r); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := tw.Close(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func fileSHA(p string) (string, error) {
	f, err := os.Open(p) // #nosec G304 -- the writer's own file
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
