// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package initapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"golang.org/x/crypto/ssh"

	initv1 "github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1"
	"github.com/Sneakers-PAM/sneakers-appliance/gen/go/sneakers/appliance/init/v1/initv1connect"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/initapi"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/keycustody/keycustodytest"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/phase"
	"github.com/Sneakers-PAM/sneakers-appliance/internal/secureboot"
)

// serveCustody serves a key-file custody, initialized as first boot does on
// a box with Secure Boot off, to peers allow admits.
func serveCustody(t *testing.T, allow func(uint32) bool) initv1connect.KeyCustodyServiceClient {
	t.Helper()
	return serveCustodyIn(t, allow, phase.Normal)
}

// serveCustodyIn is serveCustody on a box in the boot phase p.
func serveCustodyIn(t *testing.T, allow func(uint32) bool, p phase.Phase) initv1connect.KeyCustodyServiceClient {
	t.Helper()
	kc := keycustody.New(keycustody.Deps{Disk: &keycustodytest.Disk{}, SealedDir: t.TempDir(), Phase: func() phase.Phase { return p }})
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

func escrowJSON(t *testing.T, items map[string]string) []byte {
	t.Helper()
	e := keycustody.EscrowContents{Version: 1, StateKey: make([]byte, keycustody.KeySize), Items: map[string][]byte{}}
	for n, v := range items {
		e.Items[n] = []byte(v)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// An escrow comes in at first boot: what the box hasn't sealed is sealed
// from it, what it has stays, and the answer names both and never a value.
func TestKeyCustodyImportsAnEscrowInFirstboot(t *testing.T) {
	c := serveCustodyIn(t, func(uid uint32) bool { return uid == me() }, phase.Firstboot)
	ctx := context.Background()
	if _, err := c.Seal(ctx, connect.NewRequest(&initv1.SealRequest{Name: "root-key", Secret: []byte("this box's own")})); err != nil {
		t.Fatal(err)
	}
	out, err := c.ImportEscrow(ctx, connect.NewRequest(&initv1.ImportEscrowRequest{Escrow: escrowJSON(t, map[string]string{
		"root-key": "the old box's", "product-sneakers-vault-root-key": "old vault key",
	})}))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(out.Msg.GetImported(), ","); got != "product-sneakers-vault-root-key" {
		t.Errorf("imported %q", got)
	}
	if got := strings.Join(out.Msg.GetKept(), ","); got != "root-key" {
		t.Errorf("kept %q", got)
	}
	for name, want := range map[string]string{"root-key": "this box's own", "product-sneakers-vault-root-key": "old vault key"} {
		u, err := c.Unseal(ctx, connect.NewRequest(&initv1.UnsealRequest{Name: name}))
		if err != nil || string(u.Msg.GetSecret()) != want {
			t.Errorf("%s: %q %v", name, u.Msg.GetSecret(), err)
		}
	}
}

func TestKeyCustodyRefusesAnImportOutsideFirstbootOrWithNothingNew(t *testing.T) {
	ctx := context.Background()
	allow := func(uid uint32) bool { return uid == me() }
	esc := escrowJSON(t, map[string]string{"product-sneakers-totp-key": "secret value"})
	normal := serveCustodyIn(t, allow, phase.Normal)
	_, err := normal.ImportEscrow(ctx, connect.NewRequest(&initv1.ImportEscrowRequest{Escrow: esc}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "KEYCUSTODY_PHASE") {
		t.Fatalf("outside firstboot: %v", err)
	}
	first := serveCustodyIn(t, allow, phase.Firstboot)
	if _, err := first.ImportEscrow(ctx, connect.NewRequest(&initv1.ImportEscrowRequest{Escrow: esc})); err != nil {
		t.Fatal(err)
	}
	_, err = first.ImportEscrow(ctx, connect.NewRequest(&initv1.ImportEscrowRequest{Escrow: esc}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || strings.Contains(err.Error(), "secret value") {
		t.Fatalf("a second import: %v", err)
	}
	_, err = first.ImportEscrow(ctx, connect.NewRequest(&initv1.ImportEscrowRequest{Escrow: []byte("not an escrow secret-in-error?")}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument || strings.Contains(err.Error(), "not an escrow secret-in-error?") {
		t.Fatalf("a bad escrow must be invalid and must not echo its bytes: %v", err)
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
