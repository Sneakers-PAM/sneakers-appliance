// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

package k0s_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

// The product reset (docs/upgrades.md#removing-the-product): a lab box set
// up the whole way gets the lab product, whose data stand-in writes its
// marker under /var/lib/sneakers-data. `sneakers reset` over SSH, as the
// owner with a new authenticator code and the product's name typed, takes
// the product away: its data and image links are gone, the bundle is kept
// as the staged one, and the box's admins, key, :8443 certificate,
// network settings and Base OS stay, with the reset in the OS audit log.
// Apply on the Product card installs it again from the staged bundle: the
// data stand-in starts with new data, and the box makes a new setup token.
func TestAProductResetRemovesTheProductAndKeepsTheBox(t *testing.T) {
	img, keys, bundle := os.Getenv("SNEAKERS_IMAGE"), os.Getenv("SNEAKERS_KEYS"), os.Getenv("SNEAKERS_PRODUCT")
	harness.Need(t, []string{"mcopy", "ssh", "ssh-keygen"}, img, keys, bundle)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Minute)
	defer cancel()

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
	sshPort, adminPort := freePort(t), freePort(t)
	opts := func(d string) harness.Options {
		return harness.Options{SecureBoot: harness.OffWithKeys, Keys: keys, MemMiB: 4096, Disks: []harness.Disk{{Image: d}}, Timeout: 70 * time.Minute,
			HostFwd: []string{fmt.Sprintf("tcp:127.0.0.1:%d-:22", sshPort), fmt.Sprintf("tcp:127.0.0.1:%d-:8443", adminPort)}}
	}
	vm := harness.Boot(t, opts(marked))
	alice := firstBoot(t, vm, adminPort)
	vm.WaitExit(5 * time.Minute)
	box := harness.Boot(t, opts(vm.Disk(0)))
	box.Expect(`sneakers-init: phase=normal`, 5*time.Minute)

	// The install, and the product's data.
	adm := signIn(t, adminPort, alice)
	id := adm.upload(t, bundle)
	var staged struct {
		Package struct {
			Version string `json:"version"`
		} `json:"package"`
	}
	adm.call(t, "UpgradeService/StageUpdate", map[string]any{"uploadId": id}, &staged)
	adm.call(t, "UpgradeService/ApplyUpdate", map[string]any{"target": "UPDATE_TARGET_PRODUCT", "totpCode": alice.code()}, &struct{}{})
	box.Expect(`lab-hook: box running`, 30*time.Minute)
	first := dataMarker(t, box.Expect(`lab-hook: product data: \S+`, 10*time.Minute))
	tokenBefore := setupToken(ctx, t, sshPort, alice)

	before := boxSettings(ctx, t, sshPort, adminPort, alice)

	// The reset, the answers typed as the closed shell asks for them.
	out := resetOverSSH(ctx, t, sshPort, alice)
	removed := regexp.MustCompile(`Sneakers \S+ is removed: (\d+) namespaces and (\d+) objects from k0s, and (\S+ \S+) of data`).FindStringSubmatch(out)
	if removed == nil || removed[1] == "0" || removed[2] == "0" || removed[3] == "0 B" {
		t.Fatalf("the reset's answer:\n%s", out)
	}
	t.Logf("reset: %s", removed[0])
	left := box.Expect(`lab-hook: product reset: .*`, 5*time.Minute)
	if !strings.Contains(left, "data [] ") || !strings.Contains(left, "staged "+staged.Package.Version+" ") || !strings.Contains(left, "image links 0 ") {
		t.Fatalf("after the reset: %s", left)
	}
	for _, st := range []string{"lab-data", "lab-front", "hello", "edge", "sneakers-appliance-secrets", "sneakers-appliance-exposed", "box-tls"} {
		if regexp.MustCompile(`stacks \[.*\b` + regexp.QuoteMeta(st) + `\b`).MatchString(left) {
			t.Fatalf("the stack %s is still in k0s's manifests: %s", st, left)
		}
	}

	adm = signIn(t, adminPort, alice)
	var up struct {
		Product struct {
			InstalledVersion string `json:"installedVersion"`
			StagedVersion    string `json:"stagedVersion"`
			Running          bool   `json:"running"`
		} `json:"product"`
		History []struct {
			Action  string `json:"action"`
			Outcome string `json:"outcome"`
		} `json:"history"`
	}
	adm.call(t, "UpgradeService/GetUpgrades", map[string]any{}, &up)
	if up.Product.InstalledVersion != "" || up.Product.StagedVersion != staged.Package.Version || up.Product.Running {
		t.Fatalf("the Product card after the reset: %+v", up.Product)
	}
	if len(up.History) == 0 || up.History[0].Action != "reset" || up.History[0].Outcome != "ok" {
		t.Fatalf("the update history after the reset: %+v", up.History)
	}
	if after := boxSettings(ctx, t, sshPort, adminPort, alice); after != before {
		t.Fatalf("the box's settings changed:\nbefore %s\nafter  %s", before, after)
	}
	if e := auditEntry(t, adm, "product.reset"); e.Actor != "alice" || e.Outcome != "ok" || e.Detail["surface"] != "ssh" || e.Detail["objects"] == "" || e.Detail["objects"] == "0" {
		t.Fatalf("the audit entry: %+v", e)
	}
	if help, _ := ssh(ctx, sshPort, alice, "help"); strings.Contains(help, "Sneakers commands") {
		t.Fatalf("the shell still offers the product's commands:\n%s", help)
	}

	// Apply on the Product card installs it again: new data, a new setup
	// token.
	adm.call(t, "UpgradeService/ApplyUpdate", map[string]any{"target": "UPDATE_TARGET_PRODUCT", "totpCode": alice.code()}, &struct{}{})
	again := dataMarker(t, box.Expect(`lab-hook: after the reinstall: product data: \S+`, 30*time.Minute))
	if again == first {
		t.Fatalf("the reinstalled product has the old data (%s)", first)
	}
	if tokenAfter := setupToken(ctx, t, sshPort, alice); tokenAfter == tokenBefore {
		t.Fatal("the reinstalled product has the old setup token")
	}
}

var dataMarkerRE = regexp.MustCompile(`product data: (\S+)`)

// dataMarker is the lab database's marker in a lab-hook line: when it
// first started on this data.
func dataMarker(t *testing.T, line string) string {
	t.Helper()
	m := dataMarkerRE.FindStringSubmatch(line)
	if m == nil || m[1] == "none" {
		t.Fatalf("the lab database wrote no data: %s", line)
	}
	return m[1]
}

var tokenRE = regexp.MustCompile(`(?m)^\s{4}(\S+)\s*$`)

// setupToken is the lab product's setup token, as the shell shows it.
func setupToken(ctx context.Context, t *testing.T, port int, alice *lab) string {
	t.Helper()
	out, err := ssh(ctx, port, alice, "sneakers", "setup-token")
	m := tokenRE.FindStringSubmatch(out)
	if err != nil || m == nil {
		t.Fatalf("sneakers setup-token: %v:\n%s", err, out)
	}
	return m[1]
}

// boxSettings are what the reset keeps, in one line: the host name, the
// network settings, the admins and the :8443 certificate's fingerprint.
func boxSettings(ctx context.Context, t *testing.T, sshPort, adminPort int, alice *lab) string {
	t.Helper()
	var parts []string
	for _, cmd := range [][]string{{"network", "show", "-o", "json"}, {"admins", "list", "-o", "json"}, {"keys", "list", "-o", "json"}} {
		out, err := ssh(ctx, sshPort, alice, cmd...)
		if err != nil {
			t.Fatalf("%s: %v:\n%s", strings.Join(cmd, " "), err, out)
		}
		parts = append(parts, strings.Join(strings.Fields(out), " "))
	}
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", adminPort), &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- the fingerprint is what's compared
	if err != nil {
		t.Fatalf(":8443: %v", err)
	}
	sum := sha256.Sum256(conn.ConnectionState().PeerCertificates[0].Raw)
	_ = conn.Close()
	return strings.Join(append(parts, ":8443 "+hex.EncodeToString(sum[:])), " | ")
}

// auditLine is one OS audit entry as the export writes it.
type auditLine struct {
	Action  string            `json:"action"`
	Actor   string            `json:"actor"`
	Outcome string            `json:"outcome"`
	Detail  map[string]string `json:"detail"`
}

// auditEntry is the last entry for action in the exported OS audit log.
func auditEntry(t *testing.T, a *admin, action string) auditLine {
	t.Helper()
	resp, err := a.hc.Get(a.base + "/export/audit-log")
	if err != nil {
		t.Fatalf("the audit export: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the audit export: %s", resp.Status)
	}
	var last *auditLine
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var e auditLine
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Action == action {
			last = &e
		}
	}
	if last == nil {
		t.Fatalf("no %s entry in the audit log", action)
	}
	return *last
}

// lockedBuffer is a command's output as it comes.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// resetOverSSH runs `sneakers reset` as alice and answers it as it asks:
// the login's code, the product's name, then a new code for the reset.
func resetOverSSH(ctx context.Context, t *testing.T, port int, alice *lab) string {
	t.Helper()
	args := []string{"-p", fmt.Sprint(port), "-i", alice.key, "-o", "CertificateFile=" + alice.key + "-cert.pub", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10",
		"alice@127.0.0.1", "sneakers", "reset"}
	cmd := exec.CommandContext(ctx, "ssh", args...) // #nosec G204 -- test-only
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out lockedBuffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor := func(prompt string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Minute)
		for !strings.Contains(out.String(), prompt) {
			if time.Now().After(deadline) {
				_ = cmd.Process.Kill()
				t.Fatalf("no %q from the reset:\n%s", prompt, out.String())
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	_, _ = io.WriteString(in, alice.code()+"\n")
	waitFor("to confirm: ")
	_, _ = io.WriteString(in, "sneakers\n")
	waitFor("New authenticator code: ")
	_, _ = io.WriteString(in, alice.code()+"\n")
	_ = in.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("sneakers reset: %v:\n%s", err, out.String())
	}
	return out.String()
}
