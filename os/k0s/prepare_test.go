// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package k0s_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// prepareShell is the shell the tests run k0s-interim in: the box's busybox
// when SNEAKERS_TEST_BUSYBOX names it, else /bin/sh.
func prepareShell() []string {
	if bb := os.Getenv("SNEAKERS_TEST_BUSYBOX"); bb != "" {
		return []string{bb, "sh"}
	}
	return []string{"/bin/sh"}
}

func writeFile(t *testing.T, p, s string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), mode); err != nil {
		t.Fatal(err)
	}
}

// productSlot writes a product slot laid out as the Sneakers bundle's is
// once the box stages it: its header, k0s, the airgap images, the stacks,
// and with phased the files the phased bundle adds (phase-stacks next to
// switch-stacks, box-values and the exposed values RBAC).
func productSlot(t *testing.T, dir, version string, images int, phased bool) {
	t.Helper()
	writeFile(t, filepath.Join(dir, "bundle.json"), `{"format":1,"name":"sneakers-product","version":"`+version+`","arch":"amd64","kind":"product"}`, 0o644)
	writeFile(t, filepath.Join(dir, "k0s"), "#!/bin/sh\n", 0o755)
	for i := range images {
		name := fmt.Sprintf("%s%062x", version[len(version)-2:], i)
		writeFile(t, filepath.Join(dir, "images", name+".tar"), "image", 0o644)
		writeFile(t, filepath.Join(dir, "images", name+".tar.sigstore.json"), "{}", 0o644)
	}
	stacks := []string{"edge", "sneakers", "sneakers-import", "sneakers-mcp"}
	if phased {
		stacks = append(stacks, "sneakers-data", "sneakers-identity", "sneakers-services", "sneakers-front")
		writeFile(t, filepath.Join(dir, "phase-stacks"), "1 data sneakers-data\n2 identity sneakers-identity\n3 services sneakers-services\n4 front sneakers-mcp\n4 front sneakers-front\n", 0o644)
	}
	for _, st := range stacks {
		writeFile(t, filepath.Join(dir, "manifests", st, st+".yaml"), "host: "+placeholder+"\nos: baseos-version.invalid\n", 0o644) // scrub:allow=fqdn -- the reserved .invalid placeholders, never resolved
	}
	writeFile(t, filepath.Join(dir, "switch-stacks"), "mcp sneakers-mcp off\nimport sneakers-import off\n", 0o644)
	writeFile(t, filepath.Join(dir, "box-values"), placeholder+" box.fqdn\nbaseos-version.invalid box.os.version\nbaseweb-version.invalid box.web.version\n", 0o644) // scrub:allow=fqdn -- the reserved .invalid placeholders, never resolved
	writeFile(t, filepath.Join(dir, "exposed-rbac.yaml"), "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: sneakers-appliance\n", 0o644)
}

// fakeBox is a box's state for k0s-interim under root: the box's name,
// its platform settings (box values, switches, what the phase loop
// placed), its :8443 certificate, the CNI plugins kube-router installed,
// and the kernel files prepare reads.
func fakeBox(t *testing.T, root string) {
	t.Helper()
	writeFile(t, filepath.Join(root, "var/lib/sneakers/box-name"), "sneakers-0a1b2c\n", 0o644)
	writeFile(t, filepath.Join(root, "var/lib/sneakers/platform/box-values"), "box.fqdn sneakers.example.org\nbox.os.version 0.0.0-lab.1\nbox.web.version 0.0.0-lab.1\n", 0o644)
	writeFile(t, filepath.Join(root, "var/lib/sneakers/platform/switches"), "mcp on\n", 0o600)
	writeFile(t, filepath.Join(root, "var/lib/sneakers/osadmin/tls.crt"), "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n", 0o644)
	writeFile(t, filepath.Join(root, "var/lib/sneakers/osadmin/tls.key"), "KEY\n", 0o600)
	writeFile(t, filepath.Join(root, "var/lib/opt/cni/bin/bridge"), "bridge", 0o755)
	writeFile(t, filepath.Join(root, "proc/mounts"), "cgroup2 "+root+"/sys/fs/cgroup cgroup2 rw 0 0\n", 0o644)
	writeFile(t, filepath.Join(root, "proc/sys/kernel/hostname"), "sneakers\n", 0o644)
	writeFile(t, filepath.Join(root, "proc/sys/kernel/random/uuid"), "00000000-0000-4000-8000-000000000000\n", 0o644)
	writeFile(t, filepath.Join(root, "etc/k0s/k0s.yaml.tmpl"), "name: @NODE_NAME@\n", 0o644)
	writeFile(t, filepath.Join(root, "fake/ip"), "#!/bin/sh\ncase \"$*\" in \"-4 addr show dev sneakers0\") echo \"    inet 198.18.0.1/32 scope global sneakers0\";; esac\n", 0o755)
	writeFile(t, filepath.Join(root, "fake/mount"), "#!/bin/sh\n", 0o755)
}

// install points the product's current link at slot (a or b), and previous
// at the slot it named before.
func install(t *testing.T, root, slot string) {
	t.Helper()
	dir := filepath.Join(root, "var/lib/sneakers/product")
	if old, err := os.Readlink(filepath.Join(dir, "current")); err == nil {
		_ = os.Remove(filepath.Join(dir, "previous"))
		if err := os.Symlink(old, filepath.Join(dir, "previous")); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, "current")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(slot, filepath.Join(dir, "current")); err != nil {
		t.Fatal(err)
	}
}

// rooted is k0s-interim with its box paths under root and ip and mount
// faked, so prepare runs as it does on the box, against root's files.
func rooted(t *testing.T, root string) string {
	t.Helper()
	b, err := os.ReadFile("k0s-interim")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, p := range []string{"/var/lib/", "/run/sneakers", "/etc/k0s/", "/proc/", "/sys/fs/cgroup"} {
		s = strings.ReplaceAll(s, p, root+p)
	}
	s = regexp.MustCompile(`(?m)^set -eu$`).ReplaceAllString(s, "set -eu\nip() { "+root+"/fake/ip \"$@\"; }\nmount() { "+root+"/fake/mount \"$@\"; }")
	p := filepath.Join(root, "k0s-interim")
	writeFile(t, p, s, 0o755)
	return p
}

func prepare(t *testing.T, root string) (string, error) {
	t.Helper()
	sh := prepareShell()
	cmd := exec.Command(sh[0], append(sh[1:], rooted(t, root), "prepare")...) // #nosec G204 -- the repo's own script
	cmd.Env = append(os.Environ(), "PATH="+root+"/fake:/usr/sbin:/usr/bin:/sbin:/bin")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func boxImages(t *testing.T, root string) map[string]string {
	t.Helper()
	dir := filepath.Join(root, "var/lib/k0s/images")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range ents {
		l, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("%s isn't a link: %v", e.Name(), err)
		}
		out[e.Name()] = l
	}
	return out
}

// A product apply on the box: the bundle before phases (.12's layout) runs,
// then the phased Sneakers bundle (.13's: phase-stacks, switch-stacks,
// box-values, the exposed RBAC) is applied into the other slot. Each
// prepare passes, k0s gets exactly the slot's images, a phase's stacks wait
// for the phase loop, and the run is recorded on the state volume.
func TestPrepareAppliesThePhasedSneakersBundleAfterTheOneBefore(t *testing.T) {
	root := t.TempDir()
	fakeBox(t, root)
	a, b := filepath.Join(root, "var/lib/sneakers/product/a"), filepath.Join(root, "var/lib/sneakers/product/b")
	productSlot(t, a, "0.1.0-lab.sneakers.12", 25, false)
	productSlot(t, b, "0.1.0-lab.sneakers.13", 25, true)
	install(t, root, "a")
	if out, err := prepare(t, root); err != nil {
		t.Fatalf("prepare with the bundle before phases: %v\n%s", err, out)
	}
	writeFile(t, filepath.Join(root, "var/lib/sneakers/platform/phase-placed"), "sneakers-mcp\n", 0o600)
	install(t, root, "b")
	out, err := prepare(t, root)
	if err != nil {
		t.Fatalf("prepare with the phased bundle: %v\n%s", err, out)
	}
	imgs := boxImages(t, root)
	if len(imgs) != 25 {
		t.Errorf("k0s has %d image links, want the slot's 25", len(imgs))
	}
	for n, l := range imgs {
		if filepath.Dir(l) != filepath.Join(b, "images") || !strings.HasSuffix(n, ".tar") || strings.HasPrefix(n, ".") {
			t.Errorf("image link %s -> %s isn't one of the phased slot's archives", n, l)
		}
	}
	for _, st := range []string{"sneakers-data", "sneakers-identity", "sneakers-services", "sneakers-front", "sneakers-mcp"} {
		if !strings.Contains(out, "stack "+st+" waits for its phase") {
			t.Errorf("%s doesn't wait for its phase:\n%s", st, out)
		}
	}
	got, err := os.ReadFile(filepath.Join(root, "var/lib/k0s/manifests/sneakers/sneakers.yaml"))
	if err != nil || !strings.Contains(string(got), "host: sneakers.example.org") {
		t.Errorf("the always-on stack isn't placed with the box's values: %q, %v", got, err)
	}
	rec, err := os.ReadFile(filepath.Join(root, "var/lib/sneakers/k0s/prepare.log"))
	if err != nil {
		t.Fatalf("prepare keeps no record on the state volume: %v", err)
	}
	if strings.Count(string(rec), "prepare starts") != 2 || strings.Count(string(rec), "prepare done") != 2 {
		t.Errorf("the record doesn't show both runs start and finish:\n%s", rec)
	}
}

// A prepare that fails says which step it failed at, on the console and in
// its record on the state volume, which a reboot keeps.
func TestAFailedPrepareNamesItsStepInItsRecord(t *testing.T) {
	root := t.TempDir()
	fakeBox(t, root)
	productSlot(t, filepath.Join(root, "var/lib/sneakers/product/a"), "0.1.0-lab.sneakers.13", 3, true)
	install(t, root, "a")
	// A plain file where the stack directory goes: the step can't place it.
	writeFile(t, filepath.Join(root, "var/lib/k0s/manifests/sneakers/sneakers.yaml/x"), "", 0o644)
	if err := os.Chmod(filepath.Join(root, "var/lib/k0s/manifests/sneakers"), 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "var/lib/k0s/manifests/sneakers"), 0o755) })
	if os.Getuid() == 0 {
		t.Skip("root removes a read-only directory's files")
	}
	out, err := prepare(t, root)
	if err == nil {
		t.Fatalf("prepare passed with a stack it can't place:\n%s", out)
	}
	want := `prepare failed at the step "the product's stacks"`
	if !strings.Contains(out, want) {
		t.Errorf("the console doesn't name the step:\n%s", out)
	}
	rec, _ := os.ReadFile(filepath.Join(root, "var/lib/sneakers/k0s/prepare.log"))
	if !strings.Contains(string(rec), want) {
		t.Errorf("the record doesn't name the step:\n%s", rec)
	}
}

// The record is held to its cap: past 64 KiB it rolls over to
// prepare.log.1 at the next run.
func TestThePrepareRecordRollsOver(t *testing.T) {
	root := t.TempDir()
	fakeBox(t, root)
	productSlot(t, filepath.Join(root, "var/lib/sneakers/product/a"), "0.1.0-lab.sneakers.13", 1, true)
	install(t, root, "a")
	plog := filepath.Join(root, "var/lib/sneakers/k0s/prepare.log")
	writeFile(t, plog, strings.Repeat("x", 70000), 0o644)
	if out, err := prepare(t, root); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if fi, err := os.Stat(plog + ".1"); err != nil || fi.Size() != 70000 {
		t.Fatalf("the full record didn't roll over: %v", err)
	}
	if fi, err := os.Stat(plog); err != nil || fi.Size() > 4096 {
		t.Fatalf("the new record: %v", err)
	}
}

// The image links are made safely even when two runs overlap: neither
// fails, k0s ends with exactly the slot's archives, and never a half-made
// link under an archive's name.
func TestTheImageLinksSurviveTwoRunsAtOnce(t *testing.T) {
	b, err := os.ReadFile("k0s-interim")
	if err != nil {
		t.Fatal(err)
	}
	fn := regexp.MustCompile(`(?ms)^link_images\(\) \{\n.*?^\}\n`).Find(b)
	if fn == nil {
		t.Fatal("k0s-interim has no link_images function")
	}
	if !strings.Contains(string(b), `link_images "$slot" "$data/images"`) {
		t.Fatal("prepare doesn't make the image links with link_images")
	}
	root := t.TempDir()
	old, cur := filepath.Join(root, "a"), filepath.Join(root, "b")
	productSlot(t, old, "0.1.0-lab.sneakers.12", 40, false)
	productSlot(t, cur, "0.1.0-lab.sneakers.13", 40, true)
	dir := filepath.Join(root, "images")
	sh := prepareShell()
	run := func(slot string) ([]byte, error) {
		script := "set -eu\n" + string(fn) + `link_images "$1" "$2"` + "\n"
		return exec.Command(sh[0], append(sh[1:], "-c", script, "sh", slot, dir)...).CombinedOutput() // #nosec G204 -- the repo's own script
	}
	for round := range 10 {
		if out, err := run(old); err != nil {
			t.Fatalf("round %d, the earlier slot: %v: %s", round, err, out)
		}
		var wg sync.WaitGroup
		errs := make([]string, 2)
		for i := range 2 {
			wg.Go(func() {
				if out, err := run(cur); err != nil {
					errs[i] = fmt.Sprintf("%v: %s", err, out)
				}
			})
		}
		wg.Wait()
		for _, e := range errs {
			if e != "" {
				t.Fatalf("round %d: a run beside another failed: %s", round, e)
			}
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(ents) != 40 {
			t.Fatalf("round %d: %d entries, want the slot's 40 links", round, len(ents))
		}
		for _, e := range ents {
			l, err := os.Readlink(filepath.Join(dir, e.Name()))
			if err != nil || filepath.Dir(l) != filepath.Join(cur, "images") || strings.HasPrefix(e.Name(), ".") {
				t.Fatalf("round %d: %s -> %s (%v)", round, e.Name(), l, err)
			}
		}
	}
}
