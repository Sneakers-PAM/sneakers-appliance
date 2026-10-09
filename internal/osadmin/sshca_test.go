// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package osadmin_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	osadminv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/osadmin/v1"
)

// An issued key's download carries the box's user CA (for reference: it
// signed the certificate) and a known_hosts line that trusts the box's
// host CA for its name and addresses, so the first login has no host key
// prompt. Access shows the same.
func TestTheKeyDownloadCarriesTheBoxsCAs(t *testing.T) {
	b := newBox(t, false)
	alice := b.browser()
	alice.signIn("alice")
	ctx := context.Background()
	out, err := alice.access().IssueSshKey(ctx, connect.NewRequest(&osadminv1.IssueSshKeyRequest{Label: "laptop", TotpCode: b.code("alice")}))
	if err != nil {
		t.Fatal(err)
	}
	m := out.Msg
	userCA, _, _, _, err := ssh.ParseAuthorizedKey([]byte(m.GetUserCaPublicKey()))
	if err != nil || !bytes.Equal(userCA.Marshal(), b.root.PublicKey().Marshal()) {
		t.Fatalf("user CA %q %v", m.GetUserCaPublicKey(), err)
	}
	marker, hosts, hostCA, _, _, err := ssh.ParseKnownHosts([]byte(m.GetKnownHosts()))
	if err != nil || marker != "cert-authority" || !bytes.Equal(hostCA.Marshal(), b.root.HostCAPublicKey().Marshal()) {
		t.Fatalf("known_hosts %q: %q %v", m.GetKnownHosts(), marker, err)
	}
	if strings.Join(hosts, ",") != "box1.sneakers.example.org,192.0.2.10" {
		t.Fatalf("known_hosts names %v", hosts)
	}
	if m.GetKnownHostsFileName() != "known_hosts_box1.sneakers.example.org" {
		t.Fatalf("known_hosts file %q", m.GetKnownHostsFileName())
	}
	l, err := alice.access().ListAdmins(ctx, connect.NewRequest(&osadminv1.ListAdminsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if l.Msg.GetUserCaPublicKey() != m.GetUserCaPublicKey() || l.Msg.GetKnownHosts() != m.GetKnownHosts() || l.Msg.GetHostCa().GetFingerprint() != ssh.FingerprintSHA256(b.root.HostCAPublicKey()) {
		t.Fatalf("ListAdmins %v", l.Msg)
	}
}
