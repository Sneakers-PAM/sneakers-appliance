// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package initapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody/keycustodytest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
)

// serveCustody serves a key-file custody, initialized as first boot does on
// a box with Secure Boot off, to peers allow admits.
func serveCustody(t *testing.T, allow func(uint32) bool) initv1connect.KeyCustodyServiceClient {
	t.Helper()
	kc := keycustody.New(keycustody.Deps{Disk: &keycustodytest.Disk{}, SealedDir: t.TempDir()})
	if err := kc.Initialize(context.Background(), keycustody.ModeKeyfile, keycustody.SBOff); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "init.sock")
	srv, err := initapi.Listen(sock, initapi.Options{
		Allow:      allow,
		KeyCustody: kc,
		SecureBoot: secureboot.State{Supported: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	return initv1connect.NewKeyCustodyServiceClient(client(sock), "http://init.sock")
}

func TestKeyCustodyReportsTheModeAndReducedProtection(t *testing.T) {
	c := serveCustody(t, func(uid uint32) bool { return uid == me() })
	ctx := context.Background()
	m, err := c.Mode(ctx, connect.NewRequest(&initv1.ModeRequest{}))
	if err != nil || m.Msg.GetMode() != initv1.CustodyMode_CUSTODY_MODE_KEYFILE {
		t.Fatalf("mode %v %v", m, err)
	}
	p, err := c.Protection(ctx, connect.NewRequest(&initv1.ProtectionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if p.Msg.GetLevel() != initv1.ProtectionLevel_PROTECTION_LEVEL_REDUCED || p.Msg.GetReason() != string(keycustody.ReasonSecureBootOff) {
		t.Fatalf("protection %v", p.Msg)
	}
}

func TestKeyCustodySealsUnsealsAndEscrows(t *testing.T) {
	c := serveCustody(t, func(uid uint32) bool { return uid == me() })
	ctx := context.Background()
	secret := []byte("a lab-only test secret")
	if _, err := c.Seal(ctx, connect.NewRequest(&initv1.SealRequest{Name: "ssh-user-ca", Secret: secret})); err != nil {
		t.Fatal(err)
	}
	u, err := c.Unseal(ctx, connect.NewRequest(&initv1.UnsealRequest{Name: "ssh-user-ca"}))
	if err != nil || !bytes.Equal(u.Msg.GetSecret(), secret) {
		t.Fatalf("unseal %v", err)
	}
	if _, err := c.Unseal(ctx, connect.NewRequest(&initv1.UnsealRequest{Name: "vault-root"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("an item never sealed: %v", err)
	}
	if _, err := c.Seal(ctx, connect.NewRequest(&initv1.SealRequest{Name: "Not A Name", Secret: secret})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("an invalid name: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	e, err := c.Escrow(ctx, connect.NewRequest(&initv1.EscrowRequest{Recipients: []string{string(ssh.MarshalAuthorizedKey(spk))}}))
	if err != nil || len(e.Msg.GetBundle()) == 0 {
		t.Fatalf("escrow %v", err)
	}
}

func TestKeyCustodyRefusesANonRootPeer(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: the peer would be allowed")
	}
	c := serveCustody(t, initapi.RootOnly)
	if _, err := c.Unseal(context.Background(), connect.NewRequest(&initv1.UnsealRequest{Name: "ssh-user-ca"})); err == nil {
		t.Fatal("a non-root peer got through")
	}
}
