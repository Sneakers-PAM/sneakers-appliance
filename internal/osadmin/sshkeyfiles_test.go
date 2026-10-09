// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
)

// Each issued key comes with names of its own (the serial is in them), so
// a browser never adds " (1)" and the key, its -cert.pub and its .ppk
// always pair; the .ppk carries the certificate, and the OpenSSH command
// names the certificate file.
func TestAnIssuedKeysFilesPair(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	issue := func() *osadminv1.IssueSshKeyResponse {
		out, err := alice.access().IssueSshKey(ctx, connect.NewRequest(&osadminv1.IssueSshKeyRequest{Label: "laptop", TotpCode: b.code("alice")}))
		if err != nil {
			t.Fatal(err)
		}
		return out.Msg
	}
	one, two := issue(), issue()
	if one.GetFileName() == two.GetFileName() {
		t.Fatalf("two keys share the file name %q", one.GetFileName())
	}
	for _, m := range []*osadminv1.IssueSshKeyResponse{one, two} {
		f := m.GetFileName()
		if strings.ContainsAny(f, " ()/\\") || !strings.Contains(f, "alice") {
			t.Fatalf("file name %q", f)
		}
		if m.GetCertificateFileName() != f+"-cert.pub" || m.GetPpkFileName() != f+".ppk" {
			t.Fatalf("the names don't pair: %q %q %q", f, m.GetCertificateFileName(), m.GetPpkFileName())
		}
		if !strings.HasPrefix(m.GetPpk(), "PuTTY-User-Key-File-3: "+ssh.CertAlgoED25519v01+"\n") {
			t.Fatalf("the .ppk doesn't carry the certificate:\n%.80s", m.GetPpk())
		}
		if m.GetPublicKeyFileName() != f+".pub" || m.GetPemFileName() != f+".pem" {
			t.Fatalf("the .pub and .pem names don't pair: %q %q", m.GetPublicKeyFileName(), m.GetPemFileName())
		}
		sameKey(t, m)
		want := "ssh -i " + f + " -o CertificateFile=" + f + "-cert.pub alice@box1.sneakers.example.org"
		if m.GetSshCommand() != want {
			t.Fatalf("ssh command %q, want %q", m.GetSshCommand(), want)
		}
	}
}

// sameKey checks that the OpenSSH key, the .ppk, the PEM and the .pub are
// one key: one fingerprint.
func sameKey(t *testing.T, m *osadminv1.IssueSshKeyResponse) {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(m.GetPublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	want := ssh.FingerprintSHA256(pub)
	openssh, err := ssh.ParsePrivateKey([]byte(m.GetPrivateKey()))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(m.GetPem()))
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("the PEM isn't PKCS#8:\n%.60s", m.GetPem())
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("the PEM doesn't parse as PKCS#8: %v", err)
	}
	pemSigner, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	var pubLines strings.Builder
	in := false
	for _, l := range strings.Split(m.GetPpk(), "\n") {
		switch {
		case strings.HasPrefix(l, "Public-Lines: "):
			in = true
		case strings.HasPrefix(l, "Private-Lines: "):
			in = false
		case in:
			pubLines.WriteString(l)
		}
	}
	blob, err := base64.StdEncoding.DecodeString(pubLines.String())
	if err != nil {
		t.Fatal(err)
	}
	ppkPub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	cert, ok := ppkPub.(*ssh.Certificate)
	if !ok {
		t.Fatal("the .ppk's public half isn't a certificate")
	}
	for name, got := range map[string]string{
		"openssh": ssh.FingerprintSHA256(openssh.PublicKey()),
		"pem":     ssh.FingerprintSHA256(pemSigner.PublicKey()),
		"ppk":     ssh.FingerprintSHA256(cert.Key),
	} {
		if got != want {
			t.Errorf("the %s form is %s, the .pub %s", name, got, want)
		}
	}
}
