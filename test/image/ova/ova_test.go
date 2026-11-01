// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

// Package ova_test proves the file a new install starts from: the disk
// inside the kit's OVA boots fresh and first boot makes the state volumes,
// the step a root without cryptsetup, mkfs.ext4 or sgdisk fails. The release
// workflow runs it against the production OVA and won't publish without it,
// so it needs no key: the box enrols the keys its own disk carries from
// Setup Mode, as it does on a fresh VM. QEMU stands in for VMware.
package ova_test

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

// extractDisk copies the OVA's one VMDK to out.
func extractDisk(ovaPath, out string) error {
	f, err := os.Open(ovaPath)
	if err != nil {
		return err
	}
	defer f.Close()
	found := false
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if !strings.HasSuffix(h.Name, ".vmdk") {
			continue
		}
		if found {
			return fmt.Errorf("%s holds more than one VMDK", ovaPath)
		}
		found = true
		w, err := os.Create(out)
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, tr); err != nil {
			w.Close()
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
	}
	if !found {
		return fmt.Errorf("%s holds no VMDK", ovaPath)
	}
	return nil
}

func TestExtractDiskTakesTheOneVMDK(t *testing.T) {
	write := func(names ...string) string {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		for _, n := range names {
			if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(n))}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(n)); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "a.ova")
		if err := os.WriteFile(p, b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	out := filepath.Join(t.TempDir(), "disk.vmdk")
	if err := extractDisk(write("a.ovf", "a-disk1.vmdk", "a.mf"), out); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(out); err != nil || string(got) != "a-disk1.vmdk" {
		t.Fatalf("extracted %q, %v", got, err)
	}
	if err := extractDisk(write("a.ovf"), out); err == nil {
		t.Fatal("an OVA with no VMDK passed")
	}
	if err := extractDisk(write("a.vmdk", "b.vmdk"), out); err == nil {
		t.Fatal("an OVA with two VMDKs passed")
	}
}

func TestFreshOVAFirstBoot(t *testing.T) {
	ovaPath := os.Getenv("SNEAKERS_OVA")
	harness.Need(t, []string{"qemu-img"}, ovaPath)

	dir := t.TempDir()
	vmdk, raw := filepath.Join(dir, "disk.vmdk"), filepath.Join(dir, "disk.raw")
	if err := extractDisk(ovaPath, vmdk); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("qemu-img", "convert", "-f", "vmdk", "-O", "raw", vmdk, raw).CombinedOutput(); err != nil {
		t.Fatalf("qemu-img convert: %v: %s", err, out)
	}
	opts := harness.Options{SecureBoot: harness.SetupMode, TPM: true, SCSI: true}

	opts.Disks = []harness.Disk{{Image: raw, Move: true}}
	first := harness.Boot(t, opts)
	first.Expect(`sneakers-init: phase=enrol`, 5*time.Minute)
	first.Expect(`Press Enter to keep 1`, time.Minute)
	first.Type("\r")
	first.Expect(regexp.QuoteMeta(strings.TrimSpace(screens.Enrolled(screens.QEMU))), 2*time.Minute)
	first.WaitExit(2 * time.Minute)

	opts.Disks = []harness.Disk{{Image: first.Disk(0), Move: true}}
	opts.Vars, opts.TPMState = first.Vars(), first.TPMState()
	vm := harness.Boot(t, opts)
	vm.Expect(`sneakers-init: phase=firstboot protection=full`, 5*time.Minute)
	vm.Expect(`Use the TPM \(recommended\)`, time.Minute)
	vm.Type("\r")
	vm.Expect(`custody fixed \(TPM\); state and backup formatted and mounted`, 3*time.Minute)
	vm.Expect(`services: entering phase phase=firstboot`, time.Minute)
}
