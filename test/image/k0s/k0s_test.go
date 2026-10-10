// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

// Package k0s_test is the image suite's k0s run (docs/k0s.md): a lab box
// set up the whole way (the console's network and protection, then the
// :8443 setup page with the console's setup code: the first admin's
// password and TOTP, a recovery key, one sign-in) runs no k0s and serves nothing on 443 while it
// has no product bundle. The lab product bundle is then installed through
// the Updates API (upload, stage, apply), k0s starts from it with no
// registry to reach, and the hello stack answers on https://<box>/ through
// the interim edge, with 80 redirecting there. The lab product comes up in
// two phases, the hello page only once a late data stand-in is Ready, with
// no restarts, on the install and again after a power loss. The lab image's
// hook (build/lab/overlay) prints what it sees on the serial line.
package k0s_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base32"
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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/consoleui/screens"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/credentials"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/disk"
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

const hello = "hello from sneakers-appliance"

var codeOnScreen = regexp.MustCompile(`Setup code ([0-9A-Z]{4}(?:-[0-9A-Z]{4}){3})`)

// password is the first admin's password on the lab box.
const password = "image suite lab passphrase"

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
	alice := firstBoot(t, vm, adminPort)
	// The console restarts into normal operation by itself.
	vm.WaitExit(5 * time.Minute)

	next := harness.Boot(t, opts(vm.Disk(0)))
	next.Expect(`sneakers-init: phase=normal`, 5*time.Minute)
	// QEMU's user network offers no host name, so the kernel has the box's
	// own name, never "(none)".
	next.Expect(`lab-hook: host name sneakers-[0-9a-f]{8}\b`, 5*time.Minute)
	next.Expect(`lab-hook: no product bundle, no k0s`, 5*time.Minute)
	next.Expect(`services: waiting for start-when paths .*service=k0s`, time.Minute)
	if body, err := httpsGet(httpsPort); err == nil {
		t.Fatalf("443 answered before the product bundle was installed: %q", body)
	}

	// The first install, through the Updates API: upload, stage, apply.
	adm := signIn(t, adminPort, alice)
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
	adm.call(t, "UpgradeService/ApplyUpdate", map[string]any{"target": "UPDATE_TARGET_PRODUCT", "totpCode": alice.code()}, &struct{}{})
	next.Expect(`lab-hook: product bundle installed`, 2*time.Minute)
	next.Expect(`lab-hook: api up`, 25*time.Minute)
	next.Expect(`lab-hook: node ready`, 15*time.Minute)
	next.Expect(`lab-hook: hello pod ready`, 15*time.Minute)
	next.Expect(`lab-hook: box running`, 15*time.Minute)
	installed := phasesInOrder(t, next.Expect(`lab-hook: phase pods: .*`, time.Minute), "the first install")
	next.Expect(`lab-hook: edge pod ready`, 10*time.Minute)
	next.Expect(`lab-hook: root shell kubectl works`, 2*time.Minute)
	next.Expect(`lab-hook: root shell helm works`, 2*time.Minute)
	next.Expect(`lab-hook: root shell watch works`, time.Minute)
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
	// The edge routes /_box/ to sneakers-edgefall, which says the box runs.
	for {
		body, err := httpsGetPath(httpsPort, "/_box/state")
		if err == nil && strings.Contains(body, `"state":"running"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("https://<box>/_box/state from the host: %q, %v", body, err)
		}
		time.Sleep(time.Second)
	}
	// The box-state stream comes through the pinned Traefik unbuffered:
	// the first event (the current state) arrives at once, not when a
	// buffer fills or the stream ends.
	if line, err := firstEvent(httpsPort, 5*time.Second); err != nil || !strings.Contains(line, `"state":"running"`) {
		t.Fatalf("https://<box>/_box/events from the host: %q, %v", line, err)
	}
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
	if out, err := ssh(ctx, sshPort, alice, "status", "-o", "json"); err != nil || !strings.Contains(out, `"normal"`) {
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

	// A power loss: nothing stops the product, and after the boot the
	// kubelet restarts every container in its old pod at once. The box
	// quiesces them and brings the phases up again in order, with new pods
	// that never restarted (docs/upgrades.md#the-phases).
	next.Stop()
	after := harness.Boot(t, opts(next.Disk(0)))
	after.Expect(`sneakers-init: phase=normal`, 5*time.Minute)
	after.Expect(`lab-hook: hello pod ready`, 25*time.Minute)
	after.Expect(`lab-hook: box running`, 25*time.Minute)
	again := phasesInOrder(t, after.Expect(`lab-hook: phase pods: .*`, time.Minute), "after a power loss")
	t.Logf("after a power loss: %s", after.Expect(`lab-hook: scaling events: .*`, time.Minute))
	if old := oldPods(installed, again); len(old) > 0 {
		t.Fatalf("after a power loss: %v are the first install's pods, restarted in place, not quiesced", old)
	}
	// With every container restarting at once, no pod's network is set up
	// twice at the same time (the CNI plugin's "exec: already started").
	if bad := sandboxErrors(after.Expect(`lab-hook: sandbox events: .*`, time.Minute)); len(bad) > 0 {
		t.Fatalf("after a power loss: %d FailedCreatePodSandBox events with exec: already started: %v", len(bad), bad)
	}
}

// phasePod is one phased pod as the lab hook prints it.
type phasePod struct {
	restarts       int
	started, ready time.Time
}

// Each pod in the line ends with ';', with no space before the next.
var phasePodRE = regexp.MustCompile(`([\w-]+) restarts=(\d+) started=([^;\s]+) ready=([^;\s]+)`)

// readPhasePods reads the lab hook's phase pods line, one pod per match.
func readPhasePods(line string) (map[string]phasePod, error) {
	pods := map[string]phasePod{}
	for _, m := range phasePodRE.FindAllStringSubmatch(line, -1) {
		var p phasePod
		var err error
		if _, err = fmt.Sscan(m[2], &p.restarts); err == nil {
			if p.started, err = time.Parse(time.RFC3339, m[3]); err == nil {
				p.ready, err = time.Parse(time.RFC3339, m[4])
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%q doesn't read: %w", m[0], err)
		}
		pods[m[1]] = p
	}
	return pods, nil
}

// phasesInOrder checks the lab hook's phase pods line: every phased pod
// is Ready with no restarts, and the front phase's pod started only once
// the data phase's was Ready. It answers the pods.
func phasesInOrder(t *testing.T, line, when string) map[string]phasePod {
	t.Helper()
	pods, err := readPhasePods(line)
	if err != nil {
		t.Fatalf("%s: %v", when, err)
	}
	for name, p := range pods {
		if p.restarts != 0 {
			t.Errorf("%s: the %s pod restarted %d times: %s", when, name, p.restarts, line)
		}
	}
	data, okD := pods["lab-db"]
	front, okF := pods["hello"]
	if !okD || !okF {
		t.Fatalf("%s: the phase pods line names %v: %s", when, pods, line)
	}
	if front.started.Before(data.ready) {
		t.Fatalf("%s: the front phase started at %s, before the data phase was Ready at %s", when, front.started, data.ready)
	}
	t.Logf("%s: data Ready at %s, front started at %s, no restarts", when, data.ready, front.started)
	return pods
}

// oldPods are the pods of after that before already had: the same name
// and start time, so restarted in place rather than made new.
func oldPods(before, after map[string]phasePod) []string {
	var out []string
	for name, p := range after {
		if b, ok := before[name]; ok && b.started.Equal(p.started) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// sandboxErrors are the FailedCreatePodSandBox event messages in the lab
// hook's sandbox events line that carry the CNI plugin's "exec: already
// started" race: a pod's network set up twice at once.
func sandboxErrors(line string) []string {
	var out []string
	_, events, _ := strings.Cut(line, "sandbox events: ")
	for _, e := range strings.Split(events, ";") {
		if strings.Contains(e, "exec: already started") {
			out = append(out, e)
		}
	}
	return out
}

var k0sRestarted = regexp.MustCompile(`services: exited .*restart=true service=k0s\b`)

// lab is the first admin as the test holds her: the TOTP secret and the
// SSH key the box issued.
type lab struct {
	secret   []byte
	lastStep uint64
	key      string
}

// code is a TOTP code for a step not used yet: the box takes each step's
// code once, so the test waits for the next step when it has to.
func (l *lab) code() string {
	for credentials.Step(time.Now()) <= l.lastStep {
		time.Sleep(time.Second)
	}
	l.lastStep = credentials.Step(time.Now())
	return credentials.TOTP(l.secret, time.Now())
}

// firstBoot drives first boot to "Setup is complete": the network and the
// protection (Secure Boot off) on the console, then the :8443 setup page
// with the console's setup code: the first admin alice with a password and
// a TOTP secret, an SSH key the box issues, a recovery key, the network
// and protection steps, and one sign-in.
func firstBoot(t *testing.T, vm *harness.VM, adminPort int) *lab {
	t.Helper()
	vm.ExpectScreen(`type "`+screens.TypedNoSecureBoot+`" and press Enter`, 5*time.Minute)
	vm.Press(screens.TypedNoSecureBoot + "\r")
	vm.ExpectScreen(`Press Enter to continue`, 2*time.Minute)
	vm.Press("\r")
	vm.ExpectScreen(`Open this address in your browser:`, 5*time.Minute)
	code := codeOnScreen.FindStringSubmatch(vm.ExpectScreen(`Setup code [0-9A-Z]{4}(?:-[0-9A-Z]{4}){3}`, 3*time.Minute))[1]

	a := browser(t, adminPort)
	var red struct {
		CsrfToken string `json:"csrfToken"`
	}
	a.call(t, "SetupService/RedeemCode", map[string]any{"code": code}, &red)
	a.csrf = red.CsrfToken
	var begin struct {
		Totp struct {
			ID     string `json:"id"`
			Secret string `json:"secret"`
		} `json:"totp"`
	}
	a.call(t, "SetupService/BeginCredentials", map[string]any{"admin": "alice", "password": password}, &begin)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(begin.Totp.Secret)
	if err != nil {
		t.Fatal(err)
	}
	alice := &lab{secret: secret}
	var done struct {
		Session struct {
			CsrfToken string `json:"csrfToken"`
		} `json:"session"`
	}
	a.call(t, "SetupService/CompleteCredentials", map[string]any{"enrolmentId": begin.Totp.ID, "totpCode": alice.code()}, &done)
	a.csrf = done.Session.CsrfToken

	var issued struct {
		PrivateKey  string `json:"privateKey"`
		Certificate string `json:"certificate"`
	}
	a.call(t, "AccessService/IssueSshKey", map[string]any{"label": "image suite", "totpCode": alice.code()}, &issued)
	alice.key = filepath.Join(t.TempDir(), "alice")
	if err := os.WriteFile(alice.key, []byte(issued.PrivateKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alice.key+"-cert.pub", []byte(issued.Certificate+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovery, err := os.ReadFile(key(t, "recovery") + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	a.call(t, "SetupService/AddRecoveryKey", map[string]any{"publicKey": strings.TrimSpace(string(recovery)), "label": "safe"}, &struct{}{})
	for _, step := range []string{"SETUP_STEP_KIND_NETWORK", "SETUP_STEP_KIND_PROTECTION"} {
		a.call(t, "SetupService/AcknowledgeStep", map[string]any{"step": step}, &struct{}{})
	}
	a.call(t, "SetupService/AcknowledgeSingleAdmin", map[string]any{}, &struct{}{})
	signIn(t, adminPort, alice)
	vm.ExpectScreen(`Setup is done`, 2*time.Minute)
	return alice
}

// admin is a signed-in :8443 browser.
type admin struct {
	hc   *http.Client
	base string
	csrf string
}

// browser is a browser on :8443, once it answers.
func browser(t *testing.T, adminPort int) *admin {
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
			return a
		}
		if time.Now().After(deadline) {
			t.Fatalf(":8443 didn't answer: %v", err)
		}
		time.Sleep(3 * time.Second)
	}
}

// signIn signs alice in on :8443 with her password and a TOTP code.
func signIn(t *testing.T, adminPort int, alice *lab) *admin {
	t.Helper()
	a := browser(t, adminPort)
	var out struct {
		Session struct {
			CsrfToken string `json:"csrfToken"`
		} `json:"session"`
	}
	a.call(t, "SignInService/SignIn", map[string]any{"admin": "alice", "password": password, "totpCode": alice.code()}, &out)
	a.csrf = out.Session.CsrfToken
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
func httpsGet(port int) (string, error) { return httpsGetPath(port, "/") }

func httpsGetPath(port int, path string) (string, error) {
	c := http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- the box's self-signed certificate
	}}
	resp, err := c.Get(fmt.Sprintf("https://127.0.0.1:%d%s", port, path))
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(b), err
}

// firstEvent reads https://<box>/_box/events until its first data line,
// within max.
func firstEvent(port int, max time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), max)
	defer cancel()
	c := http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- the box's self-signed certificate
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d/_box/events", port), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		return "", fmt.Errorf("content type %q", ct)
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
			return data, nil
		}
	}
	return "", fmt.Errorf("no event: %v", sc.Err())
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

func key(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name+"@test", "-f", p).CombinedOutput(); err != nil { // #nosec G204 -- test-only
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	return p
}

// ssh runs command as alice with her issued key and certificate; the
// closed shell asks for a TOTP code first, read from standard input.
func ssh(ctx context.Context, port int, alice *lab, command ...string) (string, error) {
	args := []string{"-p", fmt.Sprint(port), "-i", alice.key, "-o", "CertificateFile=" + alice.key + "-cert.pub", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10",
		"alice@127.0.0.1"}
	cmd := exec.CommandContext(ctx, "ssh", append(args, command...)...) // #nosec G204 -- test-only
	cmd.Stdin = strings.NewReader(alice.code() + "\n")
	out, err := cmd.CombinedOutput()
	return string(out), err
}
