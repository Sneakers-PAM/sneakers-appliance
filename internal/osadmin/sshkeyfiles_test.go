// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"context"
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
		want := "ssh -i " + f + " -o CertificateFile=" + f + "-cert.pub alice@box1.sneakers.example.org"
		if m.GetSshCommand() != want {
			t.Fatalf("ssh command %q, want %q", m.GetSshCommand(), want)
		}
	}
}
