// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

package k0s_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

// An update from a product bundle without phases to one with them, the
// lab MCP switch on (docs/upgrades.md#the-phases): the earlier bundle's
// workloads, the switch's lab-mcp among them, carry no phase labels. Its
// lab-mcp is Ready only while hello answers, and hello is in a later
// phase than the cluster step, as the Sneakers MCP server needs the
// gateway. The box stops every one of them, waits for the cluster's own
// parts only, and brings the phases up in order with new pods.
func TestAPhasedBundleTakesOverFromOneWithoutPhases(t *testing.T) {
	img, keys, bundle, unphased := os.Getenv("SNEAKERS_IMAGE"), os.Getenv("SNEAKERS_KEYS"), os.Getenv("SNEAKERS_PRODUCT"), os.Getenv("SNEAKERS_PRODUCT_UNPHASED")
	harness.Need(t, []string{"mcopy", "ssh", "ssh-keygen"}, img, keys, bundle, unphased)

	marked := filepath.Join(t.TempDir(), "marked.raw")
	if out, err := exec.Command("cp", "--sparse=always", img, marked).CombinedOutput(); err != nil { // #nosec G204 -- test-only, fixed tool
		t.Fatalf("cp: %v: %s", err, out)
	}
	marker := filepath.Join(t.TempDir(), "lab-hook")
	if err := os.WriteFile(marker, []byte("image suite\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	esp := fmt.Sprintf("%s@@%d", marked, disk.Installed()[0].Start)
	if out, err := exec.Command("mcopy", "-i", esp, marker, "::/lab-hook").CombinedOutput(); err != nil { // #nosec G204 -- as above
		t.Fatalf("mcopy: %v: %s", err, out)
	}
	adminPort, httpsPort := freePort(t), freePort(t)
	opts := func(d string) harness.Options {
		return harness.Options{SecureBoot: harness.OffWithKeys, Keys: keys, MemMiB: 4096, Disks: []harness.Disk{{Image: d}}, Timeout: 70 * time.Minute,
			HostFwd: []string{fmt.Sprintf("tcp:127.0.0.1:%d-:8443", adminPort), fmt.Sprintf("tcp:127.0.0.1:%d-:443", httpsPort)}}
	}
	vm := harness.Boot(t, opts(marked))
	alice := firstBoot(t, vm, adminPort)
	vm.WaitExit(5 * time.Minute)
	box := harness.Boot(t, opts(vm.Disk(0)))
	box.Expect(`sneakers-init: phase=normal`, 5*time.Minute)

	apply := func(file string) {
		t.Helper()
		adm := signIn(t, adminPort, alice)
		id := adm.upload(t, file)
		var staged struct {
			Package struct {
				Target string `json:"target"`
			} `json:"package"`
		}
		adm.call(t, "UpgradeService/StageUpdate", map[string]any{"uploadId": id}, &staged)
		if staged.Package.Target != "UPDATE_TARGET_PRODUCT" {
			t.Fatalf("staged %+v", staged)
		}
		adm.call(t, "UpgradeService/ApplyUpdate", map[string]any{"target": "UPDATE_TARGET_PRODUCT", "totpCode": alice.code()}, &struct{}{})
	}
	// The bundle without phases: every workload at once, the switch's
	// lab-mcp Ready once hello answers.
	apply(unphased)
	box.Expect(`lab-hook: hello pod ready`, 30*time.Minute)
	deadline := time.Now().Add(10 * time.Minute)
	for {
		body, err := httpsGet(httpsPort)
		if err == nil && strings.Contains(body, hello) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("https://<box>/ with the bundle without phases: %q, %v", body, err)
		}
		time.Sleep(3 * time.Second)
	}
	// The phased bundle takes over.
	apply(bundle)
	box.Expect(`lab-hook: phased product`, 5*time.Minute)
	box.Expect(`lab-hook: box running`, 25*time.Minute)
	pods := phasesInOrder(t, box.Expect(`lab-hook: phase pods: .*`, time.Minute), "after the update to phases")
	if _, ok := pods["lab-mcp"]; !ok {
		t.Fatalf("the switch's lab-mcp isn't a phased pod: %v", pods)
	}
	t.Logf("after the update to phases: %s", box.Expect(`lab-hook: scaling events: .*`, time.Minute))
}
