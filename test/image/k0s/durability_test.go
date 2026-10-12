// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

package k0s_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

// durabilityRows is how many rows the lab hook writes (build/lab/overlay).
const durabilityRows = "10000"

var durabilityLine = regexp.MustCompile(`lab-hook: durability: version=(\S+) rows=(\S+) start=(\S+)`)

// TestTheDatabaseKeepsEveryRow is the durability proof: the bundled
// PostgreSQL from sneakers-release's chart, with a client holding a
// session on it (build/lab/durability.sh), keeps every row through a
// phaseless product's update to a phased one, a reboot (the k0s pre-stop
// quiesce) and a power loss. The lab hook counts the rows on the box each
// time the box runs a version, and says how the server's start began:
// after the update and the reboot it must be a clean one (the server
// wrote its shutdown checkpoint); after the power loss it may recover,
// but no row may be lost.
func TestTheDatabaseKeepsEveryRow(t *testing.T) {
	img, keys := os.Getenv("SNEAKERS_IMAGE"), os.Getenv("SNEAKERS_KEYS")
	phaseless, phased := os.Getenv("SNEAKERS_DURABILITY_PHASELESS"), os.Getenv("SNEAKERS_DURABILITY_PHASED")
	harness.Need(t, []string{"mcopy", "ssh-keygen"}, img, keys, phaseless, phased)

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
	adminPort := freePort(t)
	opts := func(d string) harness.Options {
		return harness.Options{SecureBoot: harness.OffWithKeys, Keys: keys, MemMiB: 4096, Disks: []harness.Disk{{Image: d}}, Timeout: 70 * time.Minute,
			HostFwd: []string{fmt.Sprintf("tcp:127.0.0.1:%d-:8443", adminPort)}}
	}
	vm := harness.Boot(t, opts(marked))
	alice := firstBoot(t, vm, adminPort)
	vm.WaitExit(5 * time.Minute)

	box := harness.Boot(t, opts(vm.Disk(0)))
	box.Expect(`sneakers-init: phase=normal`, 5*time.Minute)
	adm := signIn(t, adminPort, alice)

	// install uploads, stages and applies a product bundle, and answers
	// the version it staged.
	install := func(bundle string) string {
		var staged struct {
			Package struct {
				Version string `json:"version"`
			} `json:"package"`
		}
		adm.call(t, "UpgradeService/StageUpdate", map[string]any{"uploadId": adm.upload(t, bundle)}, &staged)
		adm.call(t, "UpgradeService/ApplyUpdate", map[string]any{"target": "UPDATE_TARGET_PRODUCT", "totpCode": alice.code()}, &struct{}{})
		return staged.Package.Version
	}
	// rows waits for the lab hook's report of version on vm and checks
	// every row is there; it answers how the server's start began.
	rows := func(vm *harness.VM, version, when string) string {
		t.Helper()
		m := durabilityLine.FindStringSubmatch(vm.Expect(`lab-hook: durability: version=`+regexp.QuoteMeta(version)+` .*`, 30*time.Minute))
		if m[2] != durabilityRows {
			t.Fatalf("%s: %s rows, want %s: %s", when, m[2], durabilityRows, m[0])
		}
		t.Logf("%s: %s of %s rows, start %s", when, m[2], durabilityRows, m[3])
		return m[3]
	}

	// The product from before the phases, and the rows.
	v1 := install(phaseless)
	box.Expect(`lab-hook: durability: rows written`, 30*time.Minute)
	if start := rows(box, v1, "the phaseless install"); start != "first" {
		t.Fatalf("the phaseless install: the database's start was %s, want a new one", start)
	}

	// The update to the phased product: the box stops the running product
	// (the client, then the database) before k0s restarts on the new one.
	adm = signIn(t, adminPort, alice)
	v2 := install(phased)
	if start := rows(box, v2, "the update to phases"); start != "clean" {
		t.Fatalf("the update to phases: the database's start was %s: the update didn't stop it with its shutdown checkpoint", start)
	}

	// A reboot: the k0s pre-stop quiesces the product, the database last.
	adm = signIn(t, adminPort, alice)
	adm.call(t, "SignInService/StepUp", map[string]any{"totpCode": alice.code()}, &struct{}{})
	adm.call(t, "PowerService/Reboot", map[string]any{}, &struct{}{})
	box.WaitExit(10 * time.Minute)
	again := harness.Boot(t, opts(box.Disk(0)))
	again.Expect(`sneakers-init: phase=normal`, 5*time.Minute)
	if start := rows(again, v2, "the reboot"); start != "clean" {
		t.Fatalf("the reboot: the database's start was %s: the quiesce didn't stop it with its shutdown checkpoint", start)
	}

	// A power loss: nothing stops the database. It may recover, but every
	// committed row is there.
	again.Stop()
	lost := harness.Boot(t, opts(again.Disk(0)))
	lost.Expect(`sneakers-init: phase=normal`, 5*time.Minute)
	rows(lost, v2, "the power loss")
}
