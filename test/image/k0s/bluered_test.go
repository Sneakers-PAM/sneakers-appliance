// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

package k0s_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/imageupgrade"
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

// TestBlueTakesRedFromUpdatesAndRevertsToBlue is the base update path
// (docs/upgrades.md) on two lab builds of one commit: BLUE, the image, and
// RED, a newer version as its update .bin. BLUE is set up, takes RED
// through the Updates API (upload, stage, apply) and boots it; RED is
// marked good once it's up, then reverted, and BLUE boots again.
func TestBlueTakesRedFromUpdatesAndRevertsToBlue(t *testing.T) {
	img, keys, red := os.Getenv("SNEAKERS_IMAGE"), os.Getenv("SNEAKERS_KEYS"), os.Getenv("SNEAKERS_RED")
	blueV, redV := os.Getenv("SNEAKERS_BLUE_VERSION"), os.Getenv("SNEAKERS_RED_VERSION")
	// RED is a second lab build the image workflow doesn't make yet, so
	// the test skips without it even where tools are required.
	if red == "" || blueV == "" || redV == "" {
		t.Skip("SNEAKERS_RED, SNEAKERS_BLUE_VERSION and SNEAKERS_RED_VERSION name a newer lab build and both versions")
	}
	harness.Need(t, []string{"mdir", "ssh", "ssh-keygen"}, img, keys, red)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Minute)
	defer cancel()
	sshPort, adminPort := freePort(t), freePort(t)
	opts := func(d string) harness.Options {
		return harness.Options{SecureBoot: harness.OffWithKeys, Keys: keys, MemMiB: 2048, Disks: []harness.Disk{{Image: d}}, Timeout: 70 * time.Minute,
			HostFwd: []string{fmt.Sprintf("tcp:127.0.0.1:%d-:22", sshPort), fmt.Sprintf("tcp:127.0.0.1:%d-:8443", adminPort)}}
	}
	vm := harness.Boot(t, opts(img))
	alice := firstBoot(t, vm, adminPort)
	vm.WaitExit(5 * time.Minute)

	// normal waits for the box to say so over SSH; under TCG the first
	// connections after a boot can time out in the banner exchange.
	normal := func(what string) {
		t.Helper()
		var out string
		var err error
		for i := 0; i < 6; i++ {
			if out, err = ssh(ctx, sshPort, alice, "status", "-o", "json"); err == nil {
				break
			}
			t.Logf("status over SSH, try %d: %v", i+1, err)
			time.Sleep(15 * time.Second)
		}
		if err != nil || !strings.Contains(out, `"normal"`) {
			t.Fatalf("%s: status over SSH: %v: %s", what, err, out)
		}
	}
	boot := func(from *harness.VM, version string) *harness.VM {
		t.Helper()
		next := harness.Boot(t, opts(from.Disk(0)))
		next.Expect(`sneakers-init: phase=normal`, 5*time.Minute)
		next.Expect(regexp.QuoteMeta(version), 5*time.Minute)
		normal(version)
		return next
	}

	blue := boot(vm, blueV)
	t.Logf("BLUE runs %s", blueV)
	adm := signIn(t, adminPort, alice)
	id := adm.upload(t, red)
	var staged struct {
		Package struct {
			Version string `json:"version"`
			Target  string `json:"target"`
		} `json:"package"`
	}
	adm.call(t, "UpgradeService/StageUpdate", map[string]any{"uploadId": id}, &staged)
	if staged.Package.Version != redV || staged.Package.Target != "UPDATE_TARGET_BASE" {
		t.Fatalf("staged %+v; want %s, a base update", staged.Package, redV)
	}
	if e := entries(t, blue.Disk(0)); !strings.Contains(e, imageupgrade.EntryName(redV, imageupgrade.Tries, 0)) {
		t.Fatalf("after staging, the ESP holds %s; want RED with %d tries", e, imageupgrade.Tries)
	}
	adm.call(t, "UpgradeService/ApplyUpdate", map[string]any{"target": "UPDATE_TARGET_BASE", "totpCode": alice.code()}, &struct{}{})
	blue.WaitExit(5 * time.Minute)

	redVM := boot(blue, redV)
	t.Logf("RED runs %s after the apply", redV)
	// Up and healthy, RED is marked good: its entry loses the boot
	// counter, so boot counting won't fall back to BLUE.
	deadline := time.Now().Add(3 * time.Minute)
	for e := entries(t, redVM.Disk(0)); !strings.Contains(e, imageupgrade.GoodName(redV)); e = entries(t, redVM.Disk(0)) {
		if time.Now().After(deadline) {
			t.Fatalf("RED wasn't marked good: the ESP holds %s", e)
		}
		time.Sleep(10 * time.Second)
	}
	t.Logf("RED is marked good")
	adm = signIn(t, adminPort, alice)
	adm.call(t, "UpgradeService/RevertUpdate", map[string]any{"target": "UPDATE_TARGET_BASE", "totpCode": alice.code()}, &struct{}{})
	redVM.WaitExit(5 * time.Minute)
	if e := entries(t, redVM.Disk(0)); !strings.Contains(e, imageupgrade.EntryName(redV, 0, 1)) || !strings.Contains(e, imageupgrade.GoodName(blueV)) {
		t.Fatalf("after the revert, the ESP holds %s; want RED marked bad and BLUE good", e)
	}

	boot(redVM, blueV)
	t.Logf("BLUE runs %s after the revert", blueV)
}

// entries lists the boot entries on the ESP of a VM's disk. The guest
// syncs every ESP write, so it reads the same while the VM runs.
func entries(t *testing.T, img string) string {
	t.Helper()
	esp := fmt.Sprintf("%s@@%d", img, disk.Installed()[0].Start)
	out, err := exec.Command("mdir", "-b", "-i", esp, "::/"+imageupgrade.UKIDir).CombinedOutput() // #nosec G204 -- test-only, fixed tool
	if err != nil {
		t.Fatalf("mdir: %v: %s", err, out)
	}
	return strings.Join(strings.Fields(string(out)), " ")
}
