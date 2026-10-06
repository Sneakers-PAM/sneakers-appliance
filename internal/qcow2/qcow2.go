// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package qcow2 writes the qcow2 image for Proxmox VE and other KVM hosts
// (spec 1 Section 2.4), with the VM template the docs give.
package qcow2

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/codes"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/kitout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
)

//go:embed proxmox-vm.md.tmpl
var vmTemplate string

var tmpl = template.Must(template.New("proxmox").Parse(vmTemplate))

// VMDoc renders proxmox-vm.md.
func VMDoc(name, diskFile string, sizeBytes int64) string {
	var b bytes.Buffer
	if err := tmpl.Execute(&b, struct {
		Name, Disk string
		SizeGiB    int64
	}{name, diskFile, sizeBytes / disk.GiB}); err != nil {
		panic(err) // the template is embedded and its fields fixed
	}
	return b.String()
}

// QCOW2 is the qcow2 kitout format.
type QCOW2 struct{}

// Format names the format.
func (QCOW2) Format() string { return "qcow2" }

// Arches lists the supported architectures.
func (QCOW2) Arches() []string { return []string{"amd64"} }

// Write writes <base>.qcow2 and proxmox-vm.md into dir. It needs qemu-img.
func (QCOW2) Write(ctx context.Context, s *verify.State, o kitout.Options, dir string) error {
	qemuImg, err := exec.LookPath("qemu-img")
	if err != nil {
		return codes.New(codes.KitToolMissing, "the qcow2 format needs qemu-img; use the kit's container or install it")
	}
	size := o.DiskSize
	if size == 0 {
		size = disk.MinDisk
	}
	work, err := os.MkdirTemp(dir, ".qcow2-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(work) }()
	raw := filepath.Join(work, "disk.raw")
	if err := disk.WriteInstalled(raw, size, s); err != nil {
		return err
	}
	base := kitout.BaseName(s)
	out := base + ".qcow2"
	cmd := exec.CommandContext(ctx, qemuImg, "convert", "-f", "raw", "-O", "qcow2", raw, filepath.Join(dir, out)) // #nosec G204 -- qemu-img with fixed verbs
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("qcow2: qemu-img convert: %w: %s", err, b)
	}
	return os.WriteFile(filepath.Join(dir, "proxmox-vm.md"), []byte(VMDoc(base, out, size)), 0o600)
}
