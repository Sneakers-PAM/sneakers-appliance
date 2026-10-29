// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package qcow2_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/kitout"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/qcow2"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/verify"
	"github.com/Sneakers-PAM/sneakers-appliance/test/kit/fixtures"
)

// The guide sets the VM up the way spec 1 Section 2.4 gives it, both the
// kit's and the release's.
func TestVMDoc(t *testing.T) {
	for name, doc := range map[string]string{
		"kit":     qcow2.VMDoc("sneakers-appliance-0.1.0-amd64.qcow2", 64<<30),
		"release": qcow2.ReleaseDoc(),
	} {
		for _, want := range []string{"--machine q35 --bios ovmf", "pre-enrolled-keys=0", "version=v2.0", "--scsihw virtio-scsi-single",
			"import-from=$IMAGE", "virtio,bridge=", "--agent enabled=1", "64 GiB", "qm agent \"$VMID\" ping"} {
			if !strings.Contains(doc, want) {
				t.Errorf("%s: missing %q", name, want)
			}
		}
		if strings.Contains(doc, "{{") || strings.Contains(doc, "<no value>") {
			t.Errorf("%s: a template field wasn't filled", name)
		}
		checkSteps(t, name, doc)
	}
	if kit := qcow2.VMDoc("x.qcow2", 64<<30); !strings.Contains(kit, "IMAGE=/root/x.qcow2") || strings.Contains(kit, "releases/download") {
		t.Errorf("the kit's guide is for the file beside it:\n%s", kit)
	}
	if rel := qcow2.ReleaseDoc(); !strings.Contains(rel, "sha256sum -c") || !strings.Contains(rel, "cosign verify-blob") || !strings.Contains(rel, "Untested on Proxmox VE") {
		t.Errorf("the release guide doesn't download and check the image, or doesn't say it's untested:\n%s", rel)
	}
}

// checkSteps: the numbered steps are the ## headings that start with a
// number, from 1 up with no gap (docs are tested like code).
func checkSteps(t *testing.T, name, doc string) {
	t.Helper()
	want := 1
	for _, l := range strings.Split(doc, "\n") {
		h, ok := strings.CutPrefix(l, "## ")
		if !ok || h == "" || h[0] < '0' || h[0] > '9' {
			continue
		}
		if !strings.HasPrefix(h, strconv.Itoa(want)+". ") {
			t.Errorf("%s: step %q, want step %d", name, h, want)
		}
		want++
	}
	if want == 1 {
		t.Errorf("%s: no numbered steps", name)
	}
}

// docs/proxmox-vm.md is ReleaseDoc's output; UPDATE=1 rewrites it.
func TestTheDocsGuideIsTheReleaseDoc(t *testing.T) {
	const path = "../../docs/proxmox-vm.md"
	want := qcow2.ReleaseDoc()
	if os.Getenv("UPDATE") != "" {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil { // #nosec G306 -- a doc in the repo
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s isn't the template's release guide; run UPDATE=1 go test ./internal/qcow2/", path)
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
