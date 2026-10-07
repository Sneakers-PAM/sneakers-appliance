// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

// Package k0s_test is the image suite's k0s run (docs/k0s.md): a lab box in
// normal operation starts k0s from the bundled images with no registry to
// reach, the node goes Ready, and the throwaway hello stack answers on its
// NodePort, inside the box and from the host. The first-boot steps can't be driven from here yet, so the
// lab image's hook (build/lab/overlay) marks setup done once the ESP holds
// a lab-hook file, and prints what it sees in normal operation.
package k0s_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

func TestNormalRunsK0sAndTheHelloStack(t *testing.T) {
	img, keys := os.Getenv("SNEAKERS_IMAGE"), os.Getenv("SNEAKERS_KEYS")
	harness.Need(t, []string{"mcopy"}, img, keys)

	// A copy of the image with the hook's marker on its ESP.
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

	port := freePort(t)
	opts := harness.Options{SecureBoot: harness.Off, Keys: keys, MemMiB: 4096, Disks: []harness.Disk{{Image: marked}},
		HostFwd: []string{fmt.Sprintf("tcp:127.0.0.1:%d-:%d", port, helloPort)}}
	first := harness.Boot(t, opts)
	first.Expect(`sneakers-init: phase=enrol`, 5*time.Minute)
	first.Expect(`type "`+screens.TypedNoSecureBoot+`" and press Enter`, time.Minute)
	first.Type(screens.TypedNoSecureBoot + "\r")
	first.Expect(`This box has no TPM`, time.Minute)
	first.Type("\r")
	first.Expect(`services: entering phase phase=firstboot`, 5*time.Minute)
	first.Expect(`lab-hook: setup marked done`, 2*time.Minute)
	// Stop kills QEMU: give the kernel's writeback (dirty pages expire after
	// 30 seconds) time to put first boot's files on the disk.
	time.Sleep(45 * time.Second)
	first.Stop()

	opts.Disks = []harness.Disk{{Image: first.Disk(0)}}
	opts.Timeout = 45 * time.Minute
	next := harness.Boot(t, opts)
	next.Expect(`sneakers-init: phase=normal`, 5*time.Minute)
	next.Expect(`lab-hook: api up`, 20*time.Minute)
	next.Expect(`lab-hook: node ready`, 15*time.Minute)
	next.Expect(`lab-hook: hello pod ready`, 15*time.Minute)
	got := next.Expect(`lab-hook: GET http://\S+:30080/ answered: .*`, 2*time.Minute)
	if !strings.Contains(got, "hello from sneakers-appliance") {
		t.Fatalf("the hello stack answered %q", got)
	}
	if strings.Contains(next.Console(), "ErrImageNeverPull") {
		t.Fatal("a pod needed an image the bundle doesn't hold")
	}

	// From outside the box, through the management address netd set.
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	deadline := time.Now().Add(2 * time.Minute)
	for {
		body, err := get(url)
		if err == nil && strings.Contains(body, "hello from sneakers-appliance") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET %s from the host: %q, %v", url, body, err)
		}
		time.Sleep(2 * time.Second)
	}
	// The hook marks setup done without the first-boot steps, so services
	// that need them (sshd with no owner key) keep failing here; only k0s
	// is checked for a crash loop.
	time.Sleep(60 * time.Second)
	if n := len(k0sRestarted.FindAllString(next.Console(), -1)); n >= harness.CrashLoopRestarts {
		t.Fatalf("k0s is crash-looping: restarted %d times", n)
	}
}

var k0sRestarted = regexp.MustCompile(`services: exited .*restart=true service=k0s\b`)

// helloPort is the hello stack's NodePort.
const helloPort = 30080

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

func get(url string) (string, error) {
	c := http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(url) // #nosec G107 -- the test's own forwarded port
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(b), err
}
