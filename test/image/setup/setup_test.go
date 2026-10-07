// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

// Package setup_test is the image suite's whole first boot, on the box a
// VMware VM is: a screen and no serial port, Secure Boot off, no TPM, and
// a NIC on QEMU's user network with 22 and 8443 forwarded. The wizard gets
// the DHCP address, the first admin's key is enrolled over SSH with the
// typed yes, a recovery key is set over SSH, the first :8443 sign-in is
// approved with `login <code>`, setup/done is written, and after a reboot
// the box is in normal operation with SSH and :8443 up.
package setup_test

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
	"github.com/Sneakers-PAM/sneakers-appliance/test/image/harness"
)

const (
	prompt  = `type "` + screens.TypedNoSecureBoot + `" and press Enter`
	keyfile = `Press Enter to continue`
	// QEMU's user network hands the first guest its first lease.
	leased = `10\.0\.2\.15/24` // scrub:allow=private-ip -- QEMU's user network
)

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

// key makes an ed25519 key pair for this run and returns its private
// key's path.
func key(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name+"@test", "-f", p).CombinedOutput(); err != nil { // #nosec G204 -- test-only
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	return p
}

// ssh runs one closed-shell command as user with key, feeding stdin.
func ssh(ctx context.Context, port int, user, key, stdin string, command ...string) (string, error) {
	args := []string{"-p", fmt.Sprint(port), "-i", key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10",
		user + "@127.0.0.1"}
	cmd := exec.CommandContext(ctx, "ssh", append(args, command...)...) // #nosec G204 -- test-only
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// connectCall posts a Connect unary call in JSON to :8443.
func connectCall(t *testing.T, hc *http.Client, base, procedure string, in, out any) {
	t.Helper()
	body, _ := json.Marshal(in)
	resp, err := hc.Post(base+procedure, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("%s: %v", procedure, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %s: %s", procedure, resp.Status, b)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("%s: %v: %s", procedure, err, b)
	}
}

var codeOnScreen = regexp.MustCompile(`Code ([0-9A-Z]{4}-[0-9A-Z]{4})`)

func TestFirstBootToAWorkingAppliance(t *testing.T) {
	img, keys := os.Getenv("SNEAKERS_IMAGE"), os.Getenv("SNEAKERS_KEYS")
	harness.Need(t, []string{"ssh", "ssh-keygen"}, img, keys)
	sshPort, httpsPort := freePort(t), freePort(t)
	opts := func(disk string) harness.Options {
		return harness.Options{
			SecureBoot: harness.OffWithKeys, Keys: keys, Disks: []harness.Disk{{Image: disk}}, NoSerial: true,
			HostFwd: []string{fmt.Sprintf("tcp:127.0.0.1:%d-:22", sshPort), fmt.Sprintf("tcp:127.0.0.1:%d-:8443", httpsPort)},
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()
	sshAddr := fmt.Sprintf("127.0.0.1:%d", sshPort)

	vm := harness.Boot(t, opts(img))
	vm.ExpectScreen(prompt, 5*time.Minute)
	vm.Press(screens.TypedNoSecureBoot + "\r")
	vm.ExpectScreen(keyfile, 2*time.Minute)
	vm.Press("\r")

	// 1. The wizard shows the address netd took by DHCP; it's kept once
	// the checks have run (DNS and NTP fail on a network with no way out,
	// and can be skipped; the address can't).
	vm.ExpectScreen(`The box took an address by itself.*`+leased, 5*time.Minute)
	if b := banner(sshAddr); strings.HasPrefix(b, "SSH-") {
		t.Fatalf("SSH answered before the first-boot SSH step: %q", b)
	}
	vm.Press("\r")
	if m := vm.ExpectScreen(`Every check passed|c: continue anyway`, 3*time.Minute); strings.Contains(m, "continue anyway") {
		vm.Press("c\r")
	} else {
		vm.Press("\r")
	}
	vm.ExpectScreen(`Setup 2 of 5: protection.*Protection: reduced \(Secure Boot off\)`, time.Minute)
	vm.Press("\r")

	// 2. The first admin, and their key enrolled over SSH with the code
	// shown on the screen and the yes typed there. sshd listens once the
	// SSH step opened 22.
	vm.ExpectScreen(`The first admin is an owner`, time.Minute)
	vm.Press("alice\r")
	m := vm.ExpectScreen(`Code [0-9A-Z]{4}-[0-9A-Z]{4}`, 2*time.Minute)
	code := codeOnScreen.FindStringSubmatch(m)[1]
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
	select {
	case out := <-enrolled:
		if !strings.Contains(out, "Key enrolled for alice") {
			t.Fatalf("the enrolment session said: %s", out)
		}
	case <-time.After(2 * time.Minute):
		t.Fatal("the enrolment session didn't finish")
	}
	vm.ExpectScreen(`Keys enrolled so far: 1`, time.Minute)
	vm.Press("d\r")
	vm.ExpectScreen(`Setup 4 and 5: continue on :8443`, 2*time.Minute)

	// 3. A recovery key, over SSH into the closed shell.
	recovery, err := os.ReadFile(key(t, "recovery") + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	var out string
	deadline = time.Now().Add(2 * time.Minute)
	for {
		if out, err = ssh(ctx, sshPort, "alice", alice, string(recovery), "setup", "recovery-key", "--label", "safe"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("setup recovery-key: %v: %s", err, out)
		}
		time.Sleep(3 * time.Second)
	}
	vm.ExpectScreen(`\[x\] 4 Recovery`, 2*time.Minute)

	// 4. The first :8443 sign-in, approved over SSH.
	jar, _ := cookiejar.New(nil)
	var cert []byte
	hc := &http.Client{Jar: jar, Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- the box's self-signed certificate; its fingerprint is checked below
		VerifyConnection: func(cs tls.ConnectionState) error {
			cert = cs.PeerCertificates[0].Raw
			return nil
		},
	}}}
	base := fmt.Sprintf("https://127.0.0.1:%d", httpsPort)
	var begin struct {
		Code      string `json:"code"`
		PollToken string `json:"pollToken"`
	}
	deadline = time.Now().Add(2 * time.Minute)
	for {
		resp, err := hc.Get(base + "/")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf(":8443 didn't answer: %v", err)
		}
		time.Sleep(3 * time.Second)
	}
	connectCall(t, hc, base, "/sneakers.appliance.osadmin.v1.SignInService/BeginSignIn", map[string]any{}, &begin)
	if out, err := ssh(ctx, sshPort, "alice", alice, "y\n", "login", begin.Code); err != nil || !strings.Contains(out, "Signed in.") {
		t.Fatalf("login %s: %v: %s", begin.Code, err, out)
	}
	var poll struct {
		State string `json:"state"`
	}
	connectCall(t, hc, base, "/sneakers.appliance.osadmin.v1.SignInService/PollSignIn", map[string]any{"pollToken": begin.PollToken}, &poll)
	if poll.State != "SIGN_IN_STATE_APPROVED" {
		t.Fatalf("the sign-in is %s", poll.State)
	}

	// 5. With one admin the wizard asks to confirm it, then completes setup.
	vm.ExpectScreen(`This box has one admin`, 2*time.Minute)
	vm.Press("one admin\r")
	vm.ExpectScreen(`Setup is complete.*Restart to start normal operation`, 2*time.Minute)
	vm.Press("reboot\r")
	vm.WaitExit(5 * time.Minute)

	// 6. Normal operation: the dashboard, SSH into the closed shell, and
	// :8443 with the certificate the status names.
	next := harness.Boot(t, opts(vm.Disk(0)))
	next.ExpectScreen(`Sneakers-PAM appliance Status`, 5*time.Minute)
	next.ExpectScreen(`Management 10\.0\.2\.15/24`, 3*time.Minute)
	deadline = time.Now().Add(3 * time.Minute)
	for {
		if out, err = ssh(ctx, sshPort, "alice", alice, "", "status", "-o", "json"); err == nil && strings.Contains(out, `"normal"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status after the reboot: %v: %s", err, out)
		}
		time.Sleep(3 * time.Second)
	}
	resp, err := hc.Get(base + "/")
	if err != nil {
		t.Fatalf(":8443 after the reboot: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf(":8443 after the reboot: %s", resp.Status)
	}
	sum := sha256.Sum256(cert)
	fp := strings.ToUpper(hex.EncodeToString(sum[:]))
	if !strings.Contains(strings.ReplaceAll(out, ":", ""), fp) {
		t.Fatalf("the :8443 certificate %s isn't the one status names: %s", fp, out)
	}
}
