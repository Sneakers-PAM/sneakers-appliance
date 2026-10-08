// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

//go:build image

// Package setup_test is the image suite's whole first boot, on the box a
// VMware VM is: a screen and no serial port, Secure Boot off, no TPM, and
// a NIC on QEMU's user network with 22 and 8443 forwarded. The wizard gets
// the DHCP address and shows the setup code; on :8443 the code makes the
// first admin with a password and a TOTP secret, sshd comes on, the box
// issues an SSH key, a recovery key is set, one sign-in finishes setup,
// and after a reboot the box is in normal operation with SSH (the issued
// certificate, then the TOTP code) and :8443 up.
package setup_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
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
	"github.com/Sneakers-PAM/sneakers-appliance/internal/credentials"
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

// ssh runs one closed-shell command as user with key and its certificate,
// feeding stdin (the TOTP code first).
func ssh(ctx context.Context, port int, user, key, stdin string, command ...string) (string, error) {
	args := []string{"-p", fmt.Sprint(port), "-i", key, "-o", "CertificateFile=" + key + "-cert.pub", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10",
		user + "@127.0.0.1"}
	cmd := exec.CommandContext(ctx, "ssh", append(args, command...)...) // #nosec G204 -- test-only
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// connectCall posts a Connect unary call in JSON to :8443, with the
// session's CSRF token.
func connectCall(t *testing.T, hc *http.Client, base, csrf, procedure string, in, out any) {
	t.Helper()
	body, _ := json.Marshal(in)
	req, err := http.NewRequest(http.MethodPost, base+procedure, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err := hc.Do(req)
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

var codeOnScreen = regexp.MustCompile(`setup code ([0-9A-Z]{4}-[0-9A-Z]{4})`)

// totp hands out TOTP codes for steps not used yet: the box takes each
// step's code once.
type totp struct {
	secret []byte
	last   uint64
}

func (c *totp) next() string {
	for credentials.Step(time.Now()) <= c.last {
		time.Sleep(time.Second)
	}
	c.last = credentials.Step(time.Now())
	return credentials.TOTP(c.secret, time.Now())
}

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

	// 2. The setup code on the screen opens the :8443 setup page; no SSH
	// yet.
	m := vm.ExpectScreen(`setup code [0-9A-Z]{4}-[0-9A-Z]{4}`, 3*time.Minute)
	code := codeOnScreen.FindStringSubmatch(m)[1]
	if b := banner(sshAddr); strings.HasPrefix(b, "SSH-") {
		t.Fatalf("SSH answered before the first admin: %q", b)
	}
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
	deadline := time.Now().Add(2 * time.Minute)
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
	const api = "/sneakers.appliance.osadmin.v1."
	var red struct {
		CsrfToken string `json:"csrfToken"`
	}
	connectCall(t, hc, base, "", api+"SetupService/RedeemCode", map[string]any{"code": code}, &red)

	// 3. The first admin: a password and a TOTP secret. sshd comes on.
	var begin struct {
		Totp struct {
			ID     string `json:"id"`
			Secret string `json:"secret"`
		} `json:"totp"`
	}
	const password = "image suite lab passphrase"
	connectCall(t, hc, base, red.CsrfToken, api+"SetupService/BeginCredentials", map[string]any{"admin": "alice", "password": password}, &begin)
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(begin.Totp.Secret)
	if err != nil {
		t.Fatal(err)
	}
	codes := &totp{secret: secret}
	var session struct {
		Session struct {
			CsrfToken string `json:"csrfToken"`
		} `json:"session"`
	}
	connectCall(t, hc, base, red.CsrfToken, api+"SetupService/CompleteCredentials", map[string]any{"enrolmentId": begin.Totp.ID, "totpCode": codes.next()}, &session)
	csrf := session.Session.CsrfToken
	deadline = time.Now().Add(2 * time.Minute)
	for b := banner(sshAddr); !strings.HasPrefix(b, "SSH-"); b = banner(sshAddr) {
		if time.Now().After(deadline) {
			t.Fatal("sshd didn't answer after the first admin")
		}
		time.Sleep(2 * time.Second)
	}

	// 4. An SSH key the box issues, and a recovery key.
	var issued struct {
		PrivateKey  string `json:"privateKey"`
		Certificate string `json:"certificate"`
	}
	connectCall(t, hc, base, csrf, api+"AccessService/IssueSshKey", map[string]any{"label": "image suite"}, &issued)
	alice := filepath.Join(t.TempDir(), "alice")
	if err := os.WriteFile(alice, []byte(issued.PrivateKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alice+"-cert.pub", []byte(issued.Certificate+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovery, err := os.ReadFile(key(t, "recovery") + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	connectCall(t, hc, base, csrf, api+"SetupService/AddRecoveryKey", map[string]any{"publicKey": strings.TrimSpace(string(recovery)), "label": "safe"}, &struct{}{})
	vm.ExpectScreen(`\[x\] 4 Recovery`, 2*time.Minute)
	var out string
	if out, err = ssh(ctx, sshPort, "alice", alice, "000000\n", "status"); err == nil {
		t.Fatalf("a wrong TOTP code let the login through: %s", out)
	}

	// 5. The network and protection steps, one admin confirmed, one
	// sign-in, and the wizard completes setup.
	for _, step := range []string{"SETUP_STEP_KIND_NETWORK", "SETUP_STEP_KIND_PROTECTION"} {
		connectCall(t, hc, base, csrf, api+"SetupService/AcknowledgeStep", map[string]any{"step": step}, &struct{}{})
	}
	connectCall(t, hc, base, csrf, api+"SetupService/AcknowledgeSingleAdmin", map[string]any{}, &struct{}{})
	connectCall(t, hc, base, "", api+"SignInService/SignIn", map[string]any{"admin": "alice", "password": password, "totpCode": codes.next()}, &session)
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
		if out, err = ssh(ctx, sshPort, "alice", alice, codes.next()+"\n", "status", "-o", "json"); err == nil && strings.Contains(out, `"normal"`) {
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
