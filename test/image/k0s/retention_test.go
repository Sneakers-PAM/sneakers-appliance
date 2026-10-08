// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

package k0s_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/imageupgrade"
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

// stateSlack is how far the state volume may move between updates: logs
// and the audit log grow, but a leaked .bin, unpacked layout or fetched
// release is the size of a root image.
const stateSlack = 96 << 20

// espSlack allows for UKIs of different builds differing a little in size.
const espSlack = 1 << 20

// TestThreeUpdatesInARowKeepTwoReleases is retention on lab builds of one
// commit (docs/upgrades.md): the image (E) takes each update .bin in turn
// (F, G, ...) through the Updates API, boots it and marks it good. After
// every stage the ESP holds only the running release and the staged one;
// from the second update on, the ESP and the state volume stay flat. The
// last release is then reverted, and the one before it boots.
func TestThreeUpdatesInARowKeepTwoReleases(t *testing.T) {
	img, keys := os.Getenv("SNEAKERS_IMAGE"), os.Getenv("SNEAKERS_KEYS")
	first := os.Getenv("SNEAKERS_BLUE_VERSION")
	bins, vers := strings.Split(os.Getenv("SNEAKERS_UPDATES"), ","), strings.Split(os.Getenv("SNEAKERS_UPDATE_VERSIONS"), ",")
	// The image workflow builds one lab release, so the test skips there.
	if first == "" || len(bins) < 2 || len(bins) != len(vers) {
		t.Skip("SNEAKERS_BLUE_VERSION, SNEAKERS_UPDATES and SNEAKERS_UPDATE_VERSIONS name the image's version and at least two newer lab builds, in order")
	}
	harness.Need(t, []string{"mdir", "mcopy", "ssh", "ssh-keygen"}, append([]string{img, keys}, bins...)...)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(40*len(bins)+20)*time.Minute)
	defer cancel()
	sshPort, adminPort := freePort(t), freePort(t)
	opts := func(d string) harness.Options {
		return harness.Options{SecureBoot: harness.OffWithKeys, Keys: keys, MemMiB: 2048, Disks: []harness.Disk{{Image: d}}, Timeout: time.Duration(40*len(bins)+15) * time.Minute,
			HostFwd: []string{fmt.Sprintf("tcp:127.0.0.1:%d-:22", sshPort), fmt.Sprintf("tcp:127.0.0.1:%d-:8443", adminPort)}}
	}
	vm := harness.Boot(t, opts(img))
	alice := firstBoot(t, vm, adminPort)
	vm.WaitExit(5 * time.Minute)

	boot := func(from *harness.VM, version string) *harness.VM {
		t.Helper()
		next := harness.Boot(t, opts(from.Disk(0)))
		next.Expect(`sneakers-init: phase=normal`, 5*time.Minute)
		next.Expect(regexp.QuoteMeta(version), 5*time.Minute)
		var out string
		var err error
		for i := 0; i < 6; i++ {
			if out, err = ssh(ctx, sshPort, alice, "status", "-o", "json"); err == nil {
				break
			}
			time.Sleep(15 * time.Second)
		}
		if err != nil || !strings.Contains(out, `"normal"`) {
			t.Fatalf("%s: status over SSH: %v: %s", version, err, out)
		}
		return next
	}
	markedGood := func(on *harness.VM, version string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Minute)
		for e := entries(t, on.Disk(0)); !strings.Contains(e, imageupgrade.GoodName(version)); e = entries(t, on.Disk(0)) {
			if time.Now().After(deadline) {
				t.Fatalf("%s wasn't marked good: the ESP holds %s", version, e)
			}
			time.Sleep(10 * time.Second)
		}
	}

	running, prev := boot(vm, first), first
	var espSizes, stateSizes []int64
	for i, bin := range bins {
		v := vers[i]
		adm := signIn(t, adminPort, alice)
		adm.call(t, "UpgradeService/StageUpdate", map[string]any{"uploadId": adm.upload(t, bin)}, &struct{}{})
		want := []string{imageupgrade.GoodName(prev), imageupgrade.EntryName(v, imageupgrade.Tries, 0)}
		if got := strings.Fields(entries(t, running.Disk(0))); !sameSet(got, want) {
			t.Fatalf("update %d: after staging %s the ESP holds %v; want only %v", i+1, v, got, want)
		}
		adm.call(t, "UpgradeService/ApplyUpdate", map[string]any{"target": "UPDATE_TARGET_BASE", "totpCode": alice.code()}, &struct{}{})
		running.WaitExit(5 * time.Minute)
		running = boot(running, v)
		markedGood(running, v)
		var st struct {
			Disk struct {
				UsedBytes string `json:"usedBytes"`
			} `json:"disk"`
		}
		signIn(t, adminPort, alice).call(t, "StatusService/GetStatus", map[string]any{}, &st)
		var used int64
		_, _ = fmt.Sscan(st.Disk.UsedBytes, &used)
		espSizes, stateSizes = append(espSizes, espBytes(t, running.Disk(0))), append(stateSizes, used)
		t.Logf("update %d: %s runs; ESP %d bytes, state volume %d bytes used", i+1, v, espSizes[i], used)
		prev = v
	}
	for i := 2; i < len(bins); i++ {
		if d := espSizes[i] - espSizes[1]; d > espSlack || d < -espSlack {
			t.Errorf("the ESP moved by %d bytes from update 2 to update %d: %v", d, i+1, espSizes)
		}
	}
	for i := 1; i < len(bins); i++ {
		if d := stateSizes[i] - stateSizes[0]; d > stateSlack {
			t.Errorf("the state volume grew by %d bytes from update 1 to update %d: %v", d, i+1, stateSizes)
		}
	}

	last, before := vers[len(vers)-1], vers[len(vers)-2]
	signIn(t, adminPort, alice).call(t, "UpgradeService/RevertUpdate", map[string]any{"target": "UPDATE_TARGET_BASE", "totpCode": alice.code()}, &struct{}{})
	running.WaitExit(5 * time.Minute)
	boot(running, before)
	t.Logf("%s runs again after reverting from %s", before, last)
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, x := range a {
		seen[x] = true
	}
	for _, x := range b {
		if !seen[x] {
			return false
		}
	}
	return true
}

// espBytes is the size of every file on the ESP of a VM's disk.
func espBytes(t *testing.T, img string) int64 {
	t.Helper()
	esp := fmt.Sprintf("%s@@%d", img, disk.Installed()[0].Start)
	dir := t.TempDir()
	if out, err := exec.Command("mcopy", "-s", "-n", "-i", esp, "::/", dir).CombinedOutput(); err != nil { // #nosec G204 -- test-only, fixed tool
		t.Fatalf("mcopy: %v: %s", err, out)
	}
	var n int64
	err := filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			n += fi.Size()
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}
