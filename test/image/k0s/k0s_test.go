// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

// Package k0s_test is the image suite's k0s run (docs/k0s.md): a lab box
// set up the whole way (the console wizard, the first admin's key over SSH,
// the first :8443 sign-in) runs no k0s and serves nothing on 443 while it
// has no product bundle. The lab product bundle is then installed through
// the Updates API (upload, stage, apply), k0s starts from it with no
// registry to reach, and the hello stack answers on https://<box>/ through
// the interim edge, with 80 redirecting there. The lab image's hook
// (build/lab/overlay) prints what it sees on the serial line.
package k0s_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
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

const hello = "hello from sneakers-appliance"

var codeOnScreen = regexp.MustCompile(`Code ([0-9A-Z]{4}-[0-9A-Z]{4})`)

func TestTheProductBundleBringsK0sAndTheHelloStack(t *testing.T) {
	img, keys, bundle := os.Getenv("SNEAKERS_IMAGE"), os.Getenv("SNEAKERS_KEYS"), os.Getenv("SNEAKERS_PRODUCT")
	harness.Need(t, []string{"mcopy", "ssh", "ssh-keygen"}, img, keys, bundle)
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Minute)
	defer cancel()

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

	sshPort, adminPort, httpsPort, httpPort := freePort(t), freePort(t), freePort(t), freePort(t)
	opts := func(d string) harness.Options {
		return harness.Options{SecureBoot: harness.OffWithKeys, Keys: keys, MemMiB: 4096, Disks: []harness.Disk{{Image: d}}, Timeout: 70 * time.Minute,
			HostFwd: []string{
				fmt.Sprintf("tcp:127.0.0.1:%d-:22", sshPort), fmt.Sprintf("tcp:127.0.0.1:%d-:8443", adminPort),
				fmt.Sprintf("tcp:127.0.0.1:%d-:443", httpsPort), fmt.Sprintf("tcp:127.0.0.1:%d-:80", httpPort),
			}}
	}
	vm := harness.Boot(t, opts(marked))
	alice := firstBoot(ctx, t, vm, sshPort, adminPort)
	vm.Press("reboot\r")
	vm.WaitExit(5 * time.Minute)

	next := harness.Boot(t, opts(vm.Disk(0)))
	next.Expect(`sneakers-init: phase=normal`, 5*time.Minute)
	next.Expect(`lab-hook: no product bundle, no k0s`, 5*time.Minute)
	next.Expect(`services: waiting for start-when paths .*service=k0s`, time.Minute)
	if body, err := httpsGet(httpsPort); err == nil {
		t.Fatalf("443 answered before the product bundle was installed: %q", body)
	}

	// The first install, through the Updates API: upload, stage, apply.
	adm := signIn(ctx, t, sshPort, adminPort, alice)
	id := adm.upload(t, bundle)
	var staged struct {
		Package struct {
			Version string `json:"version"`
			Target  string `json:"target"`
		} `json:"package"`
	}
	adm.call(t, "UpgradeService/StageUpdate", map[string]any{"uploadId": id}, &staged)
	if staged.Package.Target != "UPDATE_TARGET_PRODUCT" {
		t.Fatalf("staged %+v", staged)
	}
	started := time.Now()
	adm.call(t, "UpgradeService/ApplyUpdate", map[string]any{"target": "UPDATE_TARGET_PRODUCT"}, &struct{}{})
	next.Expect(`lab-hook: product bundle installed`, 2*time.Minute)
	next.Expect(`lab-hook: api up`, 25*time.Minute)
	next.Expect(`lab-hook: node ready`, 15*time.Minute)
	next.Expect(`lab-hook: hello pod ready`, 15*time.Minute)
	next.Expect(`lab-hook: edge pod ready`, 10*time.Minute)
	if strings.Contains(next.Console(), "ErrImageNeverPull") {
		t.Fatal("a pod needed an image the bundle doesn't hold")
	}

	// From outside the box: https://<box>/ through the edge, and 80
	// redirecting to it.
	deadline := time.Now().Add(3 * time.Minute)
	for {
		body, err := httpsGet(httpsPort)
		if err == nil && strings.Contains(body, hello) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("https://<box>/ from the host: %q, %v", body, err)
		}
		time.Sleep(3 * time.Second)
	}
	t.Logf("the hello page answered on 443 %s after the apply", time.Since(started).Round(time.Second))
	c := http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d/", httpPort))
	if err != nil {
		t.Fatalf("http://<box>/: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 3 || !strings.HasPrefix(resp.Header.Get("Location"), "https://") {
		t.Fatalf("http://<box>/ answered %s, Location %q; want a redirect to https", resp.Status, resp.Header.Get("Location"))
	}
	// 22 and 8443 behave as before.
	if out, err := ssh(ctx, sshPort, "alice", alice, "", "status", "-o", "json"); err != nil || !strings.Contains(out, `"normal"`) {
		t.Fatalf("status over SSH: %v: %s", err, out)
	}
	var up struct {
		Product struct {
			InstalledVersion string `json:"installedVersion"`
			Running          bool   `json:"running"`
		} `json:"product"`
	}
	adm.call(t, "UpgradeService/GetUpgrades", map[string]any{}, &up)
	if up.Product.InstalledVersion != staged.Package.Version || !up.Product.Running {
		t.Fatalf("GetUpgrades.product %+v; want %s running", up.Product, staged.Package.Version)
	}
	time.Sleep(60 * time.Second)
	if n := len(k0sRestarted.FindAllString(next.Console(), -1)); n >= harness.CrashLoopRestarts {
		t.Fatalf("k0s is crash-looping: restarted %d times", n)
	}
}

var k0sRestarted = regexp.MustCompile(`services: exited .*restart=true service=k0s\b`)

// firstBoot drives the console wizard to "Setup is complete": the network,
// the protection (Secure Boot off), the first admin alice with her key
// enrolled over SSH, a recovery key and the first :8443 sign-in. It
// returns alice's private key.
func firstBoot(ctx context.Context, t *testing.T, vm *harness.VM, sshPort, adminPort int) string {
	t.Helper()
	sshAddr := fmt.Sprintf("127.0.0.1:%d", sshPort)
	vm.ExpectScreen(`type "`+screens.TypedNoSecureBoot+`" and press Enter`, 5*time.Minute)
	vm.Press(screens.TypedNoSecureBoot + "\r")
	vm.ExpectScreen(`Press Enter to continue`, 2*time.Minute)
	vm.Press("\r")
	vm.ExpectScreen(`The box took an address by itself`, 5*time.Minute)
	vm.Press("\r")
	if m := vm.ExpectScreen(`Every check passed|c: continue anyway`, 3*time.Minute); strings.Contains(m, "continue anyway") {
		vm.Press("c\r")
	} else {
		vm.Press("\r")
	}
	vm.ExpectScreen(`Setup 2 of 5: protection`, time.Minute)
	vm.Press("\r")
	vm.ExpectScreen(`The first admin is an owner`, time.Minute)
	vm.Press("alice\r")
	code := codeOnScreen.FindStringSubmatch(vm.ExpectScreen(`Code [0-9A-Z]{4}-[0-9A-Z]{4}`, 2*time.Minute))[1]
	deadline := time.Now().Add(2 * time.Minute)
	for b := banner(sshAddr); !strings.HasPrefix(b, "SSH-"); b = banner(sshAddr) {
		if time.Now().After(deadline) {
			t.Fatal("sshd didn't answer after the SSH step opened 22")
		}
		time.Sleep(2 * time.Second)
	}
	alice := key(t, "alice")
	enrolled := make(chan string, 1)
	go func() {
		out, err := ssh(ctx, sshPort, "enrol", alice, code+"\n")
		if err != nil {
			out += " (" + err.Error() + ")"
		}
		enrolled <- out
	}()
	vm.ExpectScreen(`This key wants to be a key of admin alice`, 2*time.Minute)
	vm.Press("yes\r")
	if out := <-enrolled; !strings.Contains(out, "Key enrolled for alice") {
		t.Fatalf("the enrolment session said: %s", out)
	}
	vm.ExpectScreen(`Keys enrolled so far: 1`, time.Minute)
	vm.Press("d\r")
	vm.ExpectScreen(`Setup 4 and 5: continue on :8443`, 2*time.Minute)
	recovery, err := os.ReadFile(key(t, "recovery") + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(2 * time.Minute)
	for {
		out, err := ssh(ctx, sshPort, "alice", alice, string(recovery), "setup", "recovery-key", "--label", "safe")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("setup recovery-key: %v: %s", err, out)
		}
		time.Sleep(3 * time.Second)
	}
	vm.ExpectScreen(`\[x\] 4 Recovery`, 2*time.Minute)
	signIn(ctx, t, sshPort, adminPort, alice)
	vm.ExpectScreen(`This box has one admin`, 2*time.Minute)
	vm.Press("one admin\r")
	vm.ExpectScreen(`Setup is complete`, 2*time.Minute)
	return alice
}

// admin is a signed-in :8443 browser.
type admin struct {
	hc   *http.Client
	base string
	csrf string
}

// signIn signs alice in on :8443, approving the code with `login` over SSH.
func signIn(ctx context.Context, t *testing.T, sshPort, adminPort int, alice string) *admin {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	a := &admin{base: fmt.Sprintf("https://127.0.0.1:%d", adminPort), hc: &http.Client{Jar: jar, Timeout: 10 * time.Minute, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- the box's self-signed certificate
	}}}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		resp, err := a.hc.Get(a.base + "/")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf(":8443 didn't answer: %v", err)
		}
		time.Sleep(3 * time.Second)
	}
	var begin struct {
		Code      string `json:"code"`
		PollToken string `json:"pollToken"`
	}
	a.call(t, "SignInService/BeginSignIn", map[string]any{}, &begin)
	if out, err := ssh(ctx, sshPort, "alice", alice, "y\n", "login", begin.Code); err != nil || !strings.Contains(out, "Signed in.") {
		t.Fatalf("login %s: %v: %s", begin.Code, err, out)
	}
	var poll struct {
		State   string `json:"state"`
		Session struct {
			CsrfToken string `json:"csrfToken"`
		} `json:"session"`
	}
	a.call(t, "SignInService/PollSignIn", map[string]any{"pollToken": begin.PollToken}, &poll)
	if poll.State != "SIGN_IN_STATE_APPROVED" {
		t.Fatalf("the sign-in is %s", poll.State)
	}
	a.csrf = poll.Session.CsrfToken
	return a
}

// call posts a Connect unary call in JSON to :8443.
func (a *admin) call(t *testing.T, method string, in, out any) {
	t.Helper()
	body, _ := json.Marshal(in)
	req, err := http.NewRequest(http.MethodPost, a.base+"/sneakers.appliance.osadmin.v1."+method, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", a.csrf)
	resp, err := a.hc.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %s: %s", method, resp.Status, b)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("%s: %v: %s", method, err, b)
	}
}

// upload posts the file to /upload and returns its upload id.
func (a *admin) upload(t *testing.T, file string) string {
	t.Helper()
	f, err := os.Open(file) // #nosec G304 -- the lab build's product bundle
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	req, err := http.NewRequest(http.MethodPost, a.base+"/upload", f)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-CSRF-Token", a.csrf)
	resp, err := a.hc.Do(req)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		UploadID string `json:"uploadId"`
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || json.Unmarshal(b, &out) != nil || out.UploadID == "" {
		t.Fatalf("upload: %s: %s", resp.Status, b)
	}
	return out.UploadID
}

// httpsGet fetches https://<box>/ through the forwarded 443.
func httpsGet(port int) (string, error) {
	c := http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- the box's self-signed certificate
	}}
	resp, err := c.Get(fmt.Sprintf("https://127.0.0.1:%d/", port))
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(b), err
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// banner is what answers on the forwarded port: QEMU accepts the
// connection itself, so a closed guest port shows as no banner.
func banner(addr string) string {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return ""
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n')
	return line
}

func key(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name+"@test", "-f", p).CombinedOutput(); err != nil { // #nosec G204 -- test-only
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	return p
}

func ssh(ctx context.Context, port int, user, key, stdin string, command ...string) (string, error) {
	args := []string{"-p", fmt.Sprint(port), "-i", key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10",
		user + "@127.0.0.1"}
	cmd := exec.CommandContext(ctx, "ssh", append(args, command...)...) // #nosec G204 -- test-only
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
