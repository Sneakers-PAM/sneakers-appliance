// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package qcow2_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/kitout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/qcow2"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

func TestVMDoc(t *testing.T) {
	doc := qcow2.VMDoc("sneakers-0.1.0-amd64", "sneakers-0.1.0-amd64.qcow2", 64<<30)
	for _, want := range []string{"--machine q35", "--bios ovmf", "pre-enrolled-keys=0", "version=v2.0", "virtio-scsi-single", "virtio,bridge", "--agent enabled=1", "64 GiB"} {
		if !strings.Contains(doc, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestQCOW2WriterThroughTheKit(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		if os.Getenv("SNEAKERS_REQUIRE_TOOLS") != "" {
			t.Fatal("qemu-img isn't installed and SNEAKERS_REQUIRE_TOOLS is set")
		}
		t.Skip("qemu-img isn't installed")
	}
	dir, pins := fixtures.Build(t, fixtures.Options{})
	out := t.TempDir()
	paths, err := kitout.NewWriters(qcow2.QCOW2{}).Run(context.Background(), verify.LocalLayout(dir), pins, "qcow2", kitout.Options{Out: out, KitVersion: fixtures.Version})
	if err != nil || len(paths) != 2 {
		t.Fatalf("%v %v", paths, err)
	}
	img := filepath.Join(out, "sneakers-appliance-lab-"+fixtures.Version+"-amd64.qcow2")
	info, err := exec.Command("qemu-img", "info", "--output=json", img).CombinedOutput() // #nosec G204 -- test-only, fixed tool
	if err != nil || !strings.Contains(string(info), `"format": "qcow2"`) || !strings.Contains(string(info), `"virtual-size": 68719476736`) {
		t.Fatalf("qemu-img info: %v\n%s", err, info)
	}
}
