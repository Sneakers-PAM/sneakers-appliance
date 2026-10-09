// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package ppk_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Sneakers-PAM/sneakers-appliance/internal/ppk"
)

func certified(t *testing.T) (ed25519.PrivateKey, *ssh.Certificate) {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{Key: spk, Serial: 42, CertType: ssh.UserCert, KeyId: "alice-42", ValidPrincipals: []string{"alice"},
		ValidAfter: 1, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return priv, cert
}

type parsed struct {
	fields         map[string]string
	public, secret []byte
}

func parse(t *testing.T, b []byte) parsed {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	p := parsed{fields: map[string]string{}}
	for i := 0; i < len(lines); i++ {
		k, v, ok := strings.Cut(lines[i], ": ")
		if !ok {
			t.Fatalf("line %d %q isn't a field", i, lines[i])
		}
		p.fields[k] = v
		if k != "Public-Lines" && k != "Private-Lines" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatal(err)
		}
		var s strings.Builder
		for j := 0; j < n; j++ {
			i++
			if len(lines[i]) > 64 {
				t.Fatalf("a base64 line is %d characters", len(lines[i]))
			}
			s.WriteString(lines[i])
		}
		blob, err := base64.StdEncoding.DecodeString(s.String())
		if err != nil {
			t.Fatal(err)
		}
		if k == "Public-Lines" {
			p.public = blob
		} else {
			p.secret = blob
		}
	}
	return p
}

func str(b []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) // #nosec G115 -- a test blob
}

// The file is PPK format 3 with the certificate as the public half and
// the key's seed as the private half, under the format's MAC.
func TestTheFileCarriesTheCertificate(t *testing.T) {
	priv, cert := certified(t)
	out, err := ppk.Marshal(priv, cert, "alice@box laptop")
	if err != nil {
		t.Fatal(err)
	}
	p := parse(t, out)
	if !strings.HasPrefix(string(out), "PuTTY-User-Key-File-3: "+ssh.CertAlgoED25519v01+"\n") {
		t.Fatalf("header:\n%s", out)
	}
	if p.fields["Encryption"] != "none" || p.fields["Comment"] != "alice@box laptop" {
		t.Fatalf("fields %v", p.fields)
	}
	if !bytes.Equal(p.public, cert.Marshal()) {
		t.Fatal("the public half isn't the certificate")
	}
	seed := priv.Seed()
	if got := p.secret; !bytes.HasPrefix(seed, got[4:]) || binary.BigEndian.Uint32(got) != uint32(len(got)-4) || len(bytes.TrimRight(seed, "\x00")) != len(got)-4 { // #nosec G115 -- a test length
		t.Fatal("the private half isn't the key's seed")
	}
	mac := hmac.New(sha256.New, nil)
	for _, f := range [][]byte{[]byte(ssh.CertAlgoED25519v01), []byte("none"), []byte("alice@box laptop"), p.public, p.secret} {
		mac.Write(str(f))
	}
	if p.fields["Private-MAC"] != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("the MAC doesn't check")
	}
}

func TestItRefusesACertificateForAnotherKey(t *testing.T) {
	priv, _ := certified(t)
	_, other := certified(t)
	if _, err := ppk.Marshal(priv, other, "x"); err == nil {
		t.Fatal("a certificate for another key was embedded")
	}
	mine, cert := certified(t)
	if _, err := ppk.Marshal(mine, cert, "two\nlines"); err == nil {
		t.Fatal("a two-line comment was written")
	}
}

// PuTTY's own puttygen (SNEAKERS_TEST_PUTTYGEN, 0.78 or later) loads the
// file, sees the certificate in it and gives back the same key.
func TestPuttygenLoadsTheFile(t *testing.T) {
	pg := os.Getenv("SNEAKERS_TEST_PUTTYGEN")
	if pg == "" {
		t.Skip("SNEAKERS_TEST_PUTTYGEN isn't set; point it at puttygen 0.78 or later")
	}
	priv, cert := certified(t)
	out, err := ppk.Marshal(priv, cert, "alice@box laptop")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "alice.ppk")
	if err := os.WriteFile(f, out, 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		cmd := exec.Command(pg, args...) // #nosec G204 -- the test's puttygen
		cmd.Dir = dir
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("puttygen %v: %v\n%s", args, err, b)
		}
		return string(b)
	}
	info := run(f, "-O", "cert-info")
	for _, want := range []string{"user authentication key", "Valid user names: alice", "Certificate serial number: 42"} {
		if !strings.Contains(info, want) {
			t.Errorf("cert-info lacks %q:\n%s", want, info)
		}
	}
	if line := run(f, "-L"); !strings.HasPrefix(line, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))) {
		t.Errorf("puttygen -L gave %q", line)
	}
	run(f, "-O", "private-openssh-new", "-o", filepath.Join(dir, "back"))
	b, err := os.ReadFile(filepath.Join(dir, "back"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := k.(*ed25519.PrivateKey); !ok || !bytes.Equal(*got, priv) {
		t.Fatalf("puttygen gave back another key: %T", k)
	}
}
